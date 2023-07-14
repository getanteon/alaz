package aggregator

// aggregate data from different sources
// 1. k8s
// 2. containerd
// 3. ebpf
// 4. cgroup (TODO)
// 5. docker (TODO)

import (
	"alaz/config"
	"alaz/datastore"
	"alaz/ebpf"
	"alaz/ebpf/l7_req"
	"alaz/ebpf/tcp_state"
	"alaz/log"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"alaz/k8s"

	"k8s.io/apimachinery/pkg/types"
)

type Aggregator struct {
	// listen to events from different sources
	k8sChan  <-chan interface{}
	crChan   <-chan interface{}
	ebpfChan <-chan interface{}

	// store the service map
	clusterInfo *ClusterInfo

	// send data to datastore
	ds datastore.DataStore

	dsDestination string
}

// We need to keep track of the following
// in order to build find relationships between
// connections and pods/services

type SockInfo struct {
	Pid   uint32 `json:"pid"`
	Fd    uint64 `json:"fd"`
	Saddr string `json:"saddr"`
	Sport uint16 `json:"sport"`
	Daddr string `json:"daddr"`
	Dport uint16 `json:"dport"`
}

// type SocketMap
type SocketMap struct {
	mu sync.RWMutex
	M  map[uint64]*SocketLine `json:"fdToSockLine"` // fd -> SockLine
}

type ClusterInfo struct {
	mu sync.RWMutex
	// TODO: If pod has more than one container, we need to differentiate
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	PodIPToNamespace     map[string]string `json:"podIPToNamespace"`
	ServiceIPToNamespace map[string]string `json:"serviceIPToNamespace"`

	// Pid -> SocketMap
	// pid -> fd -> {saddr, sport, daddr, dport}
	PidToSocketMap map[uint32]*SocketMap `json:"pidToSocketMap"`
}

// If we have information from the container runtimes
// we would have pid's of the containers within the pod
// and we can use that to find the podUid directly

// If we don't have the pid's of the containers
// we can use the following to find the podUid
// {saddr+sport} -> search in podIPToPodUid -> podUid
// {daddr+dport} -> search in serviceIPToServiceUid -> serviceUid
// or
// {daddr+dport} -> search in podIPToPodUid -> podUid

var (
	// default exponential backoff (*2)
	retryInterval = 20 * time.Millisecond
	retryLimit    = 10

	// 20 + 40 + 80 + 160 + 320 + 640 + 1280 + 2560 + 5120 + 10240 = 20470 ms = 20.47 s
)

var usePgDs bool = false
var useBackendDs bool = true // default to true

func NewAggregator(k8sChan <-chan interface{}, crChan <-chan interface{}, ebpfChan <-chan interface{}) *Aggregator {
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		PidToSocketMap:        make(map[uint32]*SocketMap, 0),
		PodIPToNamespace:      map[string]string{},
		ServiceIPToNamespace:  map[string]string{},
	}

	usePgDs, _ = strconv.ParseBool(os.Getenv("DS_PG"))

	if os.Getenv("DS_BACKEND") == "false" {
		useBackendDs = false
	}

	var dsPg datastore.DataStore
	if usePgDs {
		dsPg = datastore.NewRepository(config.PostgresConfig{
			Host:     os.Getenv("POSTGRES_HOST"),
			Port:     os.Getenv("POSTGRES_PORT"),
			Username: os.Getenv("POSTGRES_USER"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			DBName:   os.Getenv("POSTGRES_DB"),
		})
	}

	dsBackend := datastore.NewBackendDS(config.BackendConfig{
		Host:  os.Getenv("BACKEND_HOST"),
		Port:  os.Getenv("BACKEND_PORT"),
		Token: os.Getenv("BACKEND_AUTH_TOKEN"),
	})

	var ds datastore.DataStore
	var dsDestination string
	if useBackendDs && !usePgDs {
		ds = dsBackend
		dsDestination = "backend"
	} else if !useBackendDs && usePgDs {
		ds = dsPg
		dsDestination = "pg"
	} else if useBackendDs && usePgDs {
		// both are enabled, use backend
		ds = dsBackend
		dsDestination = "backend"
	}

	return &Aggregator{
		k8sChan:       k8sChan,
		crChan:        crChan,
		ebpfChan:      ebpfChan,
		clusterInfo:   clusterInfo,
		ds:            ds,
		dsDestination: dsDestination,
	}
}

func (a *Aggregator) Run() {
	go a.processk8s()
	go a.processCR()
	go a.processEbpf()
}

func (a *Aggregator) AdvertisePidSockMap() {
	http.HandleFunc("/pid-sock-map",
		func(w http.ResponseWriter, r *http.Request) {
			queryParam := r.URL.Query().Get("number")
			if queryParam == "" {
				http.Error(w, "Missing query parameter 'number'", http.StatusBadRequest)
				return
			}
			number, err := strconv.ParseUint(queryParam, 10, 32)
			if err != nil {
				http.Error(w, "Invalid query parameter 'number'", http.StatusBadRequest)
				return
			}
			pid := uint32(number)

			a.clusterInfo.mu.RLock()
			defer a.clusterInfo.mu.RUnlock()

			if sockMap, ok := a.clusterInfo.PidToSocketMap[pid]; !ok {
				http.Error(w, "Pid not found", http.StatusNotFound)
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(sockMap)
				return
			}
		},
	)
}

func (a *Aggregator) processk8s() {
	for data := range a.k8sChan {
		d := data.(k8s.K8sResourceMessage)
		switch d.ResourceType {
		case k8s.POD:
			a.processPod(d)
		case k8s.SERVICE:
			a.processSvc(d)
		case k8s.REPLICASET:
			a.processReplicaSet(d)
		case k8s.DEPLOYMENT:
			a.processDeployment(d)
		case k8s.ENDPOINTS:
			a.processEndpoints(d)
		case k8s.CONTAINER:
			a.processContainer(d)
		default:
			log.Logger.Warn().Msgf("unknown resource type %s", d.ResourceType)
		}
	}
}

func (a *Aggregator) processCR() {
	for data := range a.crChan {
		// TODO
		_ = data
	}
}

func (a *Aggregator) processEbpf() {
	for data := range a.ebpfChan {
		bpfEvent, ok := data.(ebpf.BpfEvent)
		if !ok {
			log.Logger.Error().Interface("ebpfData", data).Msg("error casting ebpf event")
			continue
		}
		switch bpfEvent.Type() {
		case tcp_state.TCP_CONNECT_EVENT:
			d := data.(tcp_state.TcpConnectEvent) // copy data's value
			tcpConnectEvent := tcp_state.TcpConnectEvent{
				Fd:        d.Fd,
				Timestamp: d.Timestamp,
				Type_:     d.Type_,
				Pid:       d.Pid,
				SPort:     d.SPort,
				DPort:     d.DPort,
				SAddr:     d.SAddr,
				DAddr:     d.DAddr,
			}
			go a.processTcpConnect(tcpConnectEvent)
		case l7_req.L7_EVENT:
			d := data.(l7_req.L7Event) // copy data's value

			// copy payload slice
			payload := [512]uint8{}
			copy(payload[:], d.Payload[:])

			l7Event := l7_req.L7Event{
				Fd:                  d.Fd,
				Pid:                 d.Pid,
				Status:              d.Status,
				Duration:            d.Duration,
				Protocol:            d.Protocol,
				Method:              d.Method,
				Payload:             payload,
				PayloadSize:         d.PayloadSize,
				PayloadReadComplete: d.PayloadReadComplete,
				Failed:              d.Failed,
				WriteTimeNs:         d.WriteTimeNs,
			}
			// TODO: make this concurrent, thats why we copy the data
			go a.processL7(l7Event)
		}
	}
}

func (a *Aggregator) processTcpConnect(data interface{}) {
	d := data.(tcp_state.TcpConnectEvent)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {
		// {pid,fd} -> SockInfo

		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).
			Str("saddr", d.SAddr).Uint16("sport", d.SPort).
			Str("daddr", d.DAddr).Uint16("dport", d.DPort).
			Msg("TCP_ESTABLISHED event")

		var sockMap *SocketMap
		var ok bool
		if sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]; !ok {
			sockMap = &SocketMap{
				M:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock() // unlock for reading

		if !ok {
			skLine = NewSocketLine()
			sockMap.mu.Lock() // lock for writing
			sockMap.M[d.Fd] = skLine
			sockMap.mu.Unlock() // unlock for writing
		}

		skLine.AddValue(
			d.Timestamp, // get connection timestamp from ebpf
			&SockInfo{
				Pid:   d.Pid,
				Fd:    d.Fd,
				Saddr: d.SAddr,
				Sport: d.SPort,
				Daddr: d.DAddr,
				Dport: d.DPort,
			},
		)

	} else if d.Type_ == tcp_state.EVENT_TCP_CLOSED {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).
			Str("saddr", d.SAddr).Uint16("sport", d.SPort).
			Str("daddr", d.DAddr).Uint16("dport", d.DPort).
			Uint64("closeTime", d.Timestamp).
			Msg("TCP_CLOSED event")

		var sockMap *SocketMap
		var ok bool
		if sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]; !ok {
			sockMap = &SocketMap{
				M:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
			return
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock() // unlock for reading

		if !ok {
			return
		}

		// If connection is established before, add the close event
		skLine.AddValue(
			d.Timestamp, // get connection close timestamp from ebpf
			nil,         // closed
		)
	}
}

func parseHttpPayload(request string) (method string, path string, httpVersion string) {
	// Find the first space character
	requestFirstLine := strings.Split(request, "\n")[0]
	parts := strings.Split(requestFirstLine, " ")
	if len(parts) >= 3 {
		method = parts[0]
		path = parts[1]
		httpVersion = parts[2]
	}
	return method, path, httpVersion
}

func (a *Aggregator) processL7(d l7_req.L7Event) {
	// TODO: detect early establisted connections
	// find socket info
	// change getValue time to request start time (from ebpf)

	// When request comes before TCP_ESTABLISHED event, we don't have socket info

	var sockMap *SocketMap
	var skLine *SocketLine
	var ok bool

	sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]
	if !ok {
		log.Logger.Info().Uint32("pid", d.Pid).Msg("error finding socket map")
		return
	}

	sockMap.mu.RLock() // lock for reading
	skLine, ok = sockMap.M[d.Fd]
	sockMap.mu.RUnlock() // unlock for reading

	if !ok {
		log.Logger.Info().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Msg("error finding skLine")
		return
	}

	// In case of late request, we don't have socket info
	// ESTABLISHED
	// CLOSED
	// Request (late)

	// Request (early)
	// ESTABLISHED
	// CLOSED

	// Ideal case
	// ESTABLISHED
	// Request
	// Request ...
	// CLOSED

	// Since we process events concurrently,
	// CLOSED event can be processed before ESTABLISHED event (goroutine scheduling)

	rc := retryLimit
	rt := retryInterval
	var skInfo *SockInfo
	var err error

	for {
		skInfo, err = skLine.GetValue(d.WriteTimeNs)
		if err == nil && skInfo != nil {
			break
		}
		rc--
		time.Sleep(rt)
		rt *= 2 // exponential backoff
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("retrying getting socket info fro skLine")

		if rc == 0 {
			break
		}
	}

	if rc < retryLimit && skInfo != nil {
		log.Logger.Info().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("found socket info with retry")
	}

	if err != nil || skInfo == nil {
		log.Logger.Error().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Str("method", d.Method).Uint32("status", d.Status).Str("protocol", d.Protocol).Str("payload", string(d.Payload[0:d.PayloadSize])).
			Msg("could not find !!socket info for skLine, discarding request")
		return
	}

	// assuming successful request
	reqDto := datastore.Request{
		StartTime:  time.Now().UnixMilli(),
		Latency:    d.Duration,
		FromIP:     skInfo.Saddr,
		ToIP:       skInfo.Daddr,
		Protocol:   d.Protocol,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
	}

	// parse http payload, extract path, query params, headers
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP {
		_, reqDto.Path, _ = parseHttpPayload(string(d.Payload[0:d.PayloadSize]))
		log.Logger.Debug().Str("path", reqDto.Path).Msg("path extracted from http payload")
	}

	// find pod info
	podUid, ok := a.clusterInfo.PodIPToPodUid[skInfo.Saddr]
	if !ok {
		log.Logger.Warn().Str("Saddr", skInfo.Saddr).
			Int("pid", int(d.Pid)).
			Uint64("fd", d.Fd).
			Msg("error finding pod with sockets saddr")
		return
	}

	reqDto.FromUID = string(podUid)
	reqDto.FromType = "pod"
	reqDto.FromPort = skInfo.Sport
	reqDto.ToPort = skInfo.Dport

	// find service info
	svcUid, ok := a.clusterInfo.ServiceIPToServiceUid[skInfo.Daddr]
	if ok {
		reqDto.ToUID = string(svcUid)
		reqDto.ToType = "service"
	}
	// if not found, it's 3rd party url or something else
	// ToUID and ToType will be empty

	reqDto.Completed = !d.Failed

	go func() {
		err := a.ds.PersistRequest(reqDto)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error persisting request")
		}
	}()
}
