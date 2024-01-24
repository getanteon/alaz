package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/fake"
	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/k8s"
	"github.com/ddosify/alaz/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestMain(m *testing.M) {
	// TODO: read simulation config from a file

	// TODO: this code gets mem profile at exit
	// we need to get it periodically with top output too
	// memProfFile, err := os.Create("memprof.out")
	// if err != nil {
	// 	log.Logger.Fatal().Err(err).Msg("could not create memory profile")
	// }
	// defer memProfFile.Close() // error handling omitted for example
	// defer func() {
	// 	pprof.Lookup("allocs").WriteTo(memProfFile, 0)
	// 	// if you want to check live heap objects:
	// 	// runtime.GC() // get up-to-date statistics
	// 	// pprof.Lookup("heap").WriteTo(memProfFile, 0)
	// }()

	log.Logger.Info().Msg("simulation starts...")
	conf := &SimulatorConfig{
		// TODO: get these from a config file
		kubeEventsBufferSize:     1000,
		ebpfEventsBufferSize:     100000,
		ebpfProcEventsBufferSize: 100,
		tlsAttachQueueBufferSize: 10,
	}
	go start(conf)

	<-time.After(10 * time.Second)
	PrintMemUsage()
	syscall.Kill(syscall.Getpid(), syscall.SIGINT)
}

func PrintMemUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func start(conf *SimulatorConfig) {
	// TODO: call this func from another test, and after some time send a sigkill
	// measure memory and cpu resources

	sim := CreateSimulator(conf)
	sim.Setup()

	debug.SetGCPercent(80)
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-c
		signal.Stop(c)
		cancel()
	}()

	go sim.Simulate()

	a := aggregator.NewAggregator(ctx, sim.getKubeEvents(), sim.getEbpfEvents(),
		sim.getEbpfProcEvents(), sim.getTlsAttachQueue(), sim.getDataStore())
	a.Run()

	go http.ListenAndServe(":8181", nil)

	<-ctx.Done()
	log.Logger.Info().Msg("simulation finished")
}

type Simulator struct {
	kubeEvents chan interface{} // will be sent k8s events
	// mockCollector ?
	ebpfEvents     chan interface{}
	ebpfProcEvents chan interface{}
	tlsAttachQueue chan uint32

	mockDs datastore.DataStore
}

type SimulatorConfig struct {
	// number of processes
	// pod and services
	// k8s IPs must match with tcp and l7 events produced
	// tcp and l7 events rates
	// http, http2, grpc, postgres, rabbitmq calls
	// outbound calls

	kubeEventsBufferSize     int
	ebpfEventsBufferSize     int
	ebpfProcEventsBufferSize int
	tlsAttachQueueBufferSize int
}

func CreateSimulator(conf *SimulatorConfig) *Simulator {
	return &Simulator{
		kubeEvents:     make(chan interface{}, conf.kubeEventsBufferSize),
		ebpfEvents:     make(chan interface{}, conf.ebpfEventsBufferSize),
		ebpfProcEvents: make(chan interface{}, conf.ebpfProcEventsBufferSize),
		tlsAttachQueue: make(chan uint32, conf.tlsAttachQueueBufferSize),
		mockDs:         &MockDataStore{},
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
}

func (s *Simulator) Setup() {
	// Create Kubernetes Workloads
	// K8sResourceMessage

	podCount := 30

	pods := make(map[string]*FakePod)

	for i := 0; i < podCount; i++ {
		// TODO: namespace
		podName := fake.Name()
		podIP := fake.IP()
		mainContainerImage := fake.Name()

		pods[podName] = &FakePod{
			Name:  podName,
			IP:    podIP,
			Image: mainContainerImage,
		}
	}

	for _, p := range pods {
		s.PodCreateEvent(p.Name, p.IP, p.Image)
	}

	// create services
	// then create traffic between pods and services

	s.ServiceCreateEvent("my-service", "10.123.42.99", types.UID("uid-service"))

}

func (s *Simulator) PodCreateEvent(name string, ip string, image string) {
	obj := &corev1.Pod{}
	obj.Name = name
	obj.Status.PodIP = ip
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

func (s *Simulator) Simulate() {
	// TODO: create traffic at various rates
	// tcp events and l7 events
}

func (s *Simulator) getDataStore() datastore.DataStore {
	return s.mockDs
}

type MockDataStore struct {
	// TODO: mimic backend speed and timeouts
}

func (m *MockDataStore) PersistPod(pod datastore.Pod, eventType string) error {
	log.Logger.Info().Str("pod", pod.Name).Msg("PersistPod")
	return nil
}

func (m *MockDataStore) PersistService(service datastore.Service, eventType string) error {
	log.Logger.Info().Str("service", service.Name).Msg("PersistService")
	return nil
}

func (m *MockDataStore) PersistReplicaSet(rs datastore.ReplicaSet, eventType string) error {
	log.Logger.Info().Str("replicaset", rs.Name).Msg("PersistReplicaSet")
	return nil
}

func (m *MockDataStore) PersistDeployment(d datastore.Deployment, eventType string) error {
	log.Logger.Info().Str("deployment", d.Name).Msg("PersistDeployment")
	return nil
}

func (m *MockDataStore) PersistEndpoints(e datastore.Endpoints, eventType string) error {
	log.Logger.Info().Str("endpoints", e.Name).Msg("PersistEndpoints")
	return nil
}

func (m *MockDataStore) PersistContainer(c datastore.Container, eventType string) error {
	log.Logger.Info().Str("container", c.Name).Msg("PersistContainer")
	return nil
}

func (m *MockDataStore) PersistDaemonSet(ds datastore.DaemonSet, eventType string) error {
	log.Logger.Info().Str("daemonset", ds.Name).Msg("PersistDaemonSet")
	return nil
}

func (m *MockDataStore) PersistRequest(request *datastore.Request) error {
	log.Logger.Info().Bool("isTls", request.Tls).Str("path", request.Path).Msg("PersistRequest")
	return nil
}

func (m *MockDataStore) PersistTraceEvent(trace *l7_req.TraceEvent) error {
	log.Logger.Info().Msg("PersistTraceEvent")
	return nil
}
