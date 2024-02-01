package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime/metrics"

	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/fake"
	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/config"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/ebpf/tcp_state"
	"github.com/ddosify/alaz/k8s"
	"github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/prometheus/procfs"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/stretchr/testify/assert"
)

type SimulatorConfig struct {
	// number of processes
	// pod and services
	// k8s IPs must match with tcp and l7 events produced
	// tcp and l7 events rates
	// http, http2, grpc, postgres, rabbitmq calls
	// outbound calls

	// edgeCount * edgeRate should be smaller than ebpfEventsBufferSize

	TestDuration             int `json:"testDuration"`
	MemProfInterval          int `json:"memProfInterval"`
	PodCount                 int `json:"podCount"`
	ServiceCount             int `json:"serviceCount"`
	EdgeCount                int `json:"edgeCount"`
	EdgeRate                 int `json:"edgeRate"`
	KubeEventsBufferSize     int `json:"kubeEventsBufferSize"`
	EbpfEventsBufferSize     int `json:"ebpfEventsBufferSize"`
	EbpfProcEventsBufferSize int `json:"ebpfProcEventsBufferSize"`
	TlsAttachQueueBufferSize int `json:"tlsAttachQueueBufferSize"`
	DsReqBufferSize          int `json:"dsReqBufferSize"`
}

func readSimulationConfig(path string) (*SimulatorConfig, error) {
	var conf SimulatorConfig
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &conf)
	if err != nil {
		return nil, err
	}

	return &conf, nil
}

var simLog zerolog.Logger

func TestSimulation(t *testing.T) {
	// TODO: read simulation config from a file

	// TODO: this code gets mem profile at exit
	// we need to get it periodically with top output too
	// memProfFile, err := os.Create("memprof.out")
	// if err != nil {
	// 	simLog.Fatal().Err(err).Msg("could not create memory profile")
	// }
	// defer memProfFile.Close() // error handling omitted for example
	// defer func() {
	// 	pprof.Lookup("allocs").WriteTo(memProfFile, 0)
	// 	// if you want to check live heap objects:
	// 	// runtime.GC() // get up-to-date statistics
	// 	// pprof.Lookup("heap").WriteTo(memProfFile, 0)
	// }()

	simLog = zerolog.New(os.Stdout).With().Timestamp().Logger()

	conf, err := readSimulationConfig("testconfig/config1.json")
	if err != nil {
		simLog.Fatal().Err(err).Msg("could not read simulation config")
	}

	simLog.Info().Msg("simulation starts...")

	ctx, cancel := context.WithCancel(context.Background())

	sim := CreateSimulator(ctx, conf)

	go func(ctx context.Context) {
		t := time.NewTicker(time.Duration(conf.MemProfInterval) * time.Second)
		for range t.C {
			select {
			case <-ctx.Done():
				return
			default:
				PrintMemUsage()
			}
		}
	}(ctx)

	go func() {
		<-time.After(time.Duration(conf.TestDuration) * time.Second) // test duration
		cancel()
		simLog.Info().Msg("context canceled")
	}()

	sim.start(ctx, conf)

	totalReqReadyToBeSent := sim.getDataStore().(*MockDataStore).ReadyToBeSendReq.Load()
	putIntoBackendQueue := sim.getDataStore().(*MockDataStore).SendToBackendQueueReq.Load()

	simLog.Info().Str("totalReqReadyToBeSent", ToText(totalReqReadyToBeSent)).Msg("totalReqReadyToBeSent")
	simLog.Info().Str("putIntoBackendQueue", ToText(putIntoBackendQueue)).Msg("putIntoBackendQueue")

	expectedTotalReqProcessed := uint32(conf.TestDuration * conf.EdgeCount * conf.EdgeRate)
	errorMargin := 10

	simLog.Info().Str("expectedTotalReqProcessed", ToText(expectedTotalReqProcessed)).Msg("expectedTotalReqProcessed")

	l := expectedTotalReqProcessed * uint32(100-errorMargin) / 100
	assert.GreaterOrEqual(t, totalReqReadyToBeSent, l, "actual request count is less than expected")
	assert.GreaterOrEqual(t, putIntoBackendQueue, l, "actual request count is less than expected")

	// <-time.After(time.Duration(2*conf.MemProfInterval) * time.Second) // time interval for retrival of mem usage after simulation stops
}

var memMetrics = []metrics.Sample{
	// Cumulative sum of memory allocated to the heap by the
	// application.
	{Name: "/gc/heap/allocs:bytes"},
	// Memory occupied by live objects and dead objects that have not
	// yet been marked free by the garbage collector.
	// AKA HeapInUse
	{Name: "/memory/classes/heap/objects:bytes"},
	// Count of completed GC cycles generated by the Go runtime.
	{Name: "/gc/cycles/automatic:gc-cycles"},
	// Count of all completed GC cycles.
	{Name: "/gc/cycles/total:gc-cycles"},
	// GOGC
	{Name: "/gc/gogc:percent"},
	// GOMEMLIMIT
	{Name: "/gc/gomemlimit:bytes"},
	// Memory that is completely free and eligible to be returned to
	// the underlying system, but has not been. This metric is the
	// runtime's estimate of free address space that is backed by
	// physical memory. Btw even if goruntime release a memory block, OS will reclaim it at an appropiate moment
	// not immediately. Most likely in case of a memory pressure in system.
	{Name: "/memory/classes/heap/free:bytes"},
	// Memory that is completely free and has been returned to the
	// underlying system. This metric is the runtime's estimate of free
	// address space that is still mapped into the process, but is not
	// backed by physical memory.
	// can be recognized as rate of mem page transactions between process and OS.
	{Name: "/memory/classes/heap/released:bytes"},
	// Memory that is reserved for heap objects but is not currently
	// used to hold heap objects.
	{Name: "/memory/classes/heap/unused:bytes"},
	// All memory mapped by the Go runtime into the current process
	// as read-write. Note that this does not include memory mapped
	// by code called via cgo or via the syscall package. Sum of all
	// metrics in /memory/classes.
	{Name: "/memory/classes/total:bytes"},
	// Memory allocated from the heap that is reserved for stack space,
	// whether or not it is currently in-use. Currently, this
	// represents all stack memory for goroutines. It also includes all
	// OS thread stacks in non-cgo programs. Note that stacks may be
	// allocated differently in the future, and this may change.
	{Name: "/memory/classes/heap/stacks:bytes"},
	// Count of live goroutines
	{Name: "/sched/goroutines:goroutines"},
}

// RES can be summarized as
// Instructions and static variables belong to executable are mapped on RAM (Pss_File in smaps_rollup output)
// StackInUse
// HeapInUse reported by go runtime
// Memory that are eligible to be returned to OS, but not has been by go runtime. (/memory/classes/heap/free:bytes)
// Memory that has been reserved for heap objects but unused. (/memory/classes/heap/unused:bytes)
// LazyFree pages that are returned to OS with madvise syscall but not yet reclaimed by OS.

func PrintMemUsage() {

	// Memory statistics are recorded after a GC run.
	// Trigger GC to have latest state of heap.
	// runtime.GC() // triggered each time PrintMemUsage called, preventing us observing the normal GC behaviour.
	metrics.Read(memMetrics)

	HeapInUse := bToMb(memMetrics[1].Value.Uint64())
	HeapFree := bToMb(memMetrics[6].Value.Uint64())
	HeapUnused := bToMb(memMetrics[8].Value.Uint64())
	Stack := bToMb(memMetrics[10].Value.Uint64())
	LiveGoroutines := memMetrics[11].Value.Uint64()

	fmt.Printf("Total bytes allocated: %v", bToMb(memMetrics[0].Value.Uint64()))
	fmt.Printf("\tIn-use bytes: %v", HeapInUse)
	// fmt.Printf("\tAutomatic gc cycles: %v", (memMetrics[2].Value.Uint64()))
	fmt.Printf("\tTotal gc cycles: %v", (memMetrics[3].Value.Uint64()))
	// fmt.Printf("\tGOGC percent: %v", (memMetrics[4].Value.Uint64()))
	// fmt.Printf("\tGOMEMLIMIT: %v\n", bToMb(memMetrics[5].Value.Uint64()))
	fmt.Printf("\tHeapFree: %v", HeapFree)
	fmt.Printf("\tHeapReleased: %v", bToMb(memMetrics[7].Value.Uint64()))
	fmt.Printf("\tHeapUnused: %v", HeapUnused)
	// fmt.Printf("\tTotal: %v", bToMb(memMetrics[9].Value.Uint64()))
	fmt.Printf("\tStack: %v", Stack)
	fmt.Printf("\tLiveGoroutines: %v", LiveGoroutines)

	proc, err := procfs.Self()
	if err != nil {
		simLog.Fatal().Err(err)
	}
	smapRollup, err := proc.ProcSMapsRollup()
	if err != nil {
		simLog.Fatal().Err(err)
	}

	// Anonymous pages of process that are mapped on RAM. Includes heap area.
	Anonymous := bToMb(smapRollup.Anonymous)
	// Resident Set Size, total size of memory that process has mapped on RAM.
	Rss := bToMb(smapRollup.Rss)
	// Pss_File := Rss - Anonymous // estimating instructions and static variables belongs to the executable

	fmt.Printf("\tAnonymous: %v", Anonymous)
	fmt.Printf("\tRss: %v", Rss)

	goRuntimeMetrics := (HeapInUse + HeapFree + HeapUnused + Stack)
	var diff uint64
	if Anonymous > goRuntimeMetrics {
		diff = Anonymous - goRuntimeMetrics
	} else {
		diff = goRuntimeMetrics - Anonymous
	}
	fmt.Printf("\tDiff %d\n", diff)

}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func (sim *Simulator) start(ctx context.Context, conf *SimulatorConfig) {
	// TODO: call this func from another test, and after some time send a sigkill
	// measure memory and cpu resources

	sim.Setup()

	// debug.SetGCPercent(80)
	go sim.Simulate(ctx)

	a := aggregator.NewAggregator(ctx, sim.getKubeEvents(), sim.getEbpfEvents(),
		sim.getEbpfProcEvents(), sim.getTlsAttachQueue(), sim.getDataStore())
	a.Run()

	go http.ListenAndServe(":8181", nil)

	<-sim.simDone // wait for simulation to stop generating traffic to return metrics
}

type Simulator struct {
	kubeEvents chan interface{} // will be sent k8s events
	// mockCollector ?
	ebpfEvents     chan interface{}
	ebpfProcEvents chan interface{}
	tlsAttachQueue chan uint32

	mockDs datastore.DataStore

	pods     map[string]*FakePod
	services map[string]*FakeService

	simDone chan struct{}

	conf *SimulatorConfig
}

func CreateSimulator(ctx context.Context, conf *SimulatorConfig) *Simulator {
	return &Simulator{
		kubeEvents:     make(chan interface{}, conf.KubeEventsBufferSize),
		ebpfEvents:     make(chan interface{}, conf.EbpfEventsBufferSize),
		ebpfProcEvents: make(chan interface{}, conf.EbpfProcEventsBufferSize),
		tlsAttachQueue: make(chan uint32, conf.TlsAttachQueueBufferSize),
		mockDs:         NewMockDataStore(ctx, conf),
		pods:           map[string]*FakePod{},
		services:       map[string]*FakeService{},
		simDone:        make(chan struct{}),
		conf:           conf,
	}
}

func (s *Simulator) getKubeEvents() chan interface{} {
	return s.kubeEvents
}

func (s *Simulator) getEbpfEvents() chan interface{} {
	return s.ebpfEvents
}

func (s *Simulator) getEbpfProcEvents() chan interface{} {
	return s.ebpfProcEvents
}

func (s *Simulator) getTlsAttachQueue() chan uint32 {
	return s.tlsAttachQueue
}

type FakePod struct {
	Name  string
	IP    string
	Image string
	Uid   types.UID

	//
	Pid             uint32
	Fds             map[uint64]struct{}
	OpenConnections map[uint64]uint64 // fd -> timestamp
}

type FakeService struct {
	Name string
	IP   string
	UID  types.UID
}

func (s *Simulator) Setup() {
	// Create Kubernetes Workloads
	// K8sResourceMessage

	for i := 0; i < s.conf.PodCount; i++ {
		// TODO: namespace
		podName := fake.Name()
		podIP := fake.IP(fake.WithIPv4())
		mainContainerImage := fake.Name()
		uid := types.UID(fake.Name())
		pid := rand.Uint32()

		s.pods[podName] = &FakePod{
			Name:            podName,
			IP:              podIP,
			Image:           mainContainerImage,
			Uid:             uid,
			Pid:             pid,
			Fds:             map[uint64]struct{}{},
			OpenConnections: map[uint64]uint64{},
		}
	}

	for _, p := range s.pods {
		s.PodCreateEvent(p.Name, p.IP, p.Image, p.Uid)
	}

	// create services
	// then create traffic between pods and services

	for i := 0; i < s.conf.ServiceCount; i++ {
		// TODO: namespace
		svcName := fake.Name()
		svcIP := fake.IP(fake.WithIPv4())

		s.services[svcName] = &FakeService{
			Name: svcName,
			IP:   svcIP,
			UID:  types.UID(fake.Name()),
		}
	}

	for _, svc := range s.services {
		s.ServiceCreateEvent(svc.Name, svc.IP, svc.UID)
	}
}

func (s *Simulator) PodCreateEvent(name string, ip string, image string, uid types.UID) {
	obj := &corev1.Pod{}
	obj.Name = name
	obj.Status.PodIP = ip
	obj.UID = uid
	obj.Spec.Containers = make([]corev1.Container, 0)
	obj.Spec.Containers = append(obj.Spec.Containers, corev1.Container{
		Image: image,
	})
	s.kubeEvents <- k8s.K8sResourceMessage{
		ResourceType: k8s.POD,
		EventType:    k8s.ADD,
		Object:       obj,
	}
}

func (s *Simulator) ServiceCreateEvent(name string, ip string, uid types.UID) {
	obj := &corev1.Service{}
	obj.Spec.ClusterIP = ip
	obj.Name = name
	obj.UID = uid

	s.kubeEvents <- k8s.K8sResourceMessage{
		ResourceType: k8s.SERVICE,
		EventType:    k8s.ADD,
		Object:       obj,
	}
}

func (sim *Simulator) Simulate(ctx context.Context) {
	// TODO: create traffic at various rates
	// tcp events and l7 events
	podKeys := make([]string, 0)
	svcKeys := make([]string, 0)

	for name, _ := range sim.pods {
		n := name
		podKeys = append(podKeys, n)
	}

	for name, _ := range sim.services {
		n := name
		svcKeys = append(svcKeys, n)
	}

	ec := sim.conf.EdgeCount
	// retryLimit changed to 1 on aggregator
	// processL7 exiting, stop retrying... // retry blocks workers

	wg := &sync.WaitGroup{}
	for ec > 0 {
		ec--

		// select one pod and service
		// TODO: these randoms conflict ????

		pod := sim.pods[podKeys[rand.Intn(len(podKeys))]]
		svc := sim.services[svcKeys[rand.Intn(len(svcKeys))]]

		// get a unique fd
		var fd uint64
		for {
			fd = rand.Uint64()
			if _, ok := pod.Fds[fd]; !ok {
				pod.Fds[fd] = struct{}{}
				break
			}
		}

		tx := rand.Uint64()
		pod.OpenConnections[fd] = tx
		cc := &ConnectionConfig{
			Pid:     pod.Pid,
			Fd:      fd,
			Saddr:   pod.IP,
			Daddr:   svc.IP,
			Tx:      tx,
			PodName: pod.Name,
			SvcName: svc.Name,
		}

		sim.constructSockets([]*ConnectionConfig{cc})
		wg.Add(1)
		// simulate traffic
		go func(wg *sync.WaitGroup) {
			sim.httpTraffic(ctx, &Traffic{
				pod:      pod,
				fd:       fd,
				svc:      svc,
				rate:     rate.NewLimiter(rate.Limit(sim.conf.EdgeRate), sim.conf.EdgeRate), // 1000 events per second
				protocol: l7_req.L7_PROTOCOL_HTTP,
			})
			wg.Done()
		}(wg)
	}

	simLog.Warn().Msg("waiting for traffic to stop")
	wg.Wait()
	simLog.Warn().Msg("closing simDone chan")
	close(sim.simDone)
}

type ConnectionConfig struct {
	Pid   uint32 // source pid
	Fd    uint64
	Saddr string // podIP
	Daddr string // svcIP
	Tx    uint64 // timestamp of connection start

	PodName string
	SvcName string
}

// podName -> Pid

func (sim *Simulator) constructSockets(cc []*ConnectionConfig) {
	for _, c := range cc {
		sim.tcpEstablish(c.Pid, c.Fd, c.Saddr, c.Daddr, c.Tx)
	}
}

type Traffic struct {
	pod      *FakePod
	fd       uint64
	svc      *FakeService
	rate     *rate.Limiter
	protocol string
}

func (sim *Simulator) httpTraffic(ctx context.Context, t *Traffic) {
	httpPayload := `GET /user HTTP1.1`
	payload := [1024]uint8{}
	for i, b := range []uint8(httpPayload) {
		payload[i] = b
	}

	simLog.Warn().Any("payload", payload)

	blockingLogged := false
	for {
		// time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
		select {
		case <-ctx.Done():
			return
		default:
			if t.rate.Allow() {
				// In ebpf.Program's Consume methods, in order to prevent drops on
				// ebpf maps, we send collected data using new goroutines
				// otherwise in case of blocking on internal ebpfEvents channel
				// ebpf map are likely to drop events
				// go func() {
				// TODO:! when a new goroutine spawned for each event stack rocketed

				select {
				case sim.ebpfEvents <- &l7_req.L7Event{
					Fd:                  t.fd,
					Pid:                 t.pod.Pid,
					Status:              200,
					Duration:            50,
					Protocol:            t.protocol,
					Tls:                 false,
					Method:              "",
					Payload:             payload,
					PayloadSize:         uint32(len(httpPayload)),
					PayloadReadComplete: true,
					Failed:              false,
					WriteTimeNs:         t.pod.OpenConnections[t.fd] + 10,

					// tracing purposes
					Tid:           0,
					Seq:           0,
					EventReadTime: 0,
				}:
				default:
					if !blockingLogged {
						simLog.Warn().Msg("block on ebpfEvents chan")
						blockingLogged = true
					}
				}
				// }()

			}
		}
	}

}

// saddr is matched with podIP
// {pid,fd} duo is used to socketLine struct
// socketInfo corresponding to requests timestamp is retrieved
func (sim *Simulator) tcpEstablish(srcPid uint32, fd uint64, saddr string, daddr string, tx uint64) {
	sim.ebpfEvents <- &tcp_state.TcpConnectEvent{
		Fd:        fd,
		Timestamp: tx,
		Type_:     tcp_state.EVENT_TCP_ESTABLISHED,
		Pid:       srcPid,
		SPort:     0,
		DPort:     0,
		SAddr:     saddr,
		DAddr:     daddr,
	}
}

func (s *Simulator) getDataStore() datastore.DataStore {
	return s.mockDs
}

func NewMockDataStore(ctx context.Context, conf *SimulatorConfig) *MockDataStore {
	mockBackendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		simLog.Debug().Str("path", r.URL.Path).Msg("")
		// time.Sleep(time.Duration(rand.Intn(5)) * time.Millisecond)
		fmt.Fprintf(w, "success")
	}))

	backendDs := datastore.NewBackendDS(ctx, config.BackendDSConfig{
		Host:                  mockBackendServer.URL,
		MetricsExport:         false,
		MetricsExportInterval: 10,
		ReqBufferSize:         conf.DsReqBufferSize,
	})
	return &MockDataStore{
		BackendDS:             backendDs,
		BackendServer:         mockBackendServer,
		ReadyToBeSendReq:      atomic.Uint32{},
		SendToBackendQueueReq: atomic.Uint32{},
	}

}

type MockDataStore struct {
	// Wrapper for BackendDS
	// mock backend endpoints with httptest.Server
	*datastore.BackendDS
	BackendServer *httptest.Server

	// difference between these two metrics can indicate
	// small buffer on backendDS or slow responding backend
	ReadyToBeSendReq      atomic.Uint32
	SendToBackendQueueReq atomic.Uint32
}

func (m *MockDataStore) PersistRequest(request *datastore.Request) error {
	m.ReadyToBeSendReq.Add(1)
	// m.BackendDS.PersistRequest(request) // depends on dsReqBufferSize, batchSize, batchInterval, backend latency
	m.SendToBackendQueueReq.Add(1)
	return nil
}

type Magnitude struct {
	Magnitude uint32
	Symbol    string
}

func (m *Magnitude) ToText(number uint32) string {
	return fmt.Sprintf("%.1f%s", float64(number)/float64(m.Magnitude), m.Symbol)
}

func ToText(number uint32) string {
	list := []Magnitude{
		// Magnitude{1000000000000, "T"},
		Magnitude{1000000000, "B"},
		Magnitude{1000000, "M"},
		Magnitude{1000, "K"},
	}
	for _, m := range list {
		if m.Magnitude < uint32(number) {
			return m.ToText(uint32(number))
		}
	}
	return fmt.Sprintf("%d", number)

}
