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
	"strings"
	"sync"
	"time"

	"alaz/k8s"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Aggregator struct {
	// listen to events from different sources
	k8sChan  <-chan interface{}
	crChan   <-chan interface{}
	ebpfChan <-chan interface{}

	// store the service map
	clusterInfo *ClusterInfo

	// persist data to db, backend will consume this
	repo datastore.Repository
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
	// TODO: add timestamp
}

// type SocketMap
type SocketMap struct {
	mu sync.RWMutex
	m  map[uint64]*SocketLine // fd -> SockLine
}

type ClusterInfo struct {
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

func NewAggregator(k8sChan <-chan interface{}, crChan <-chan interface{}, ebpfChan <-chan interface{}) *Aggregator {
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		PidToSocketMap:        make(map[uint32]*SocketMap, 0),
		PodIPToNamespace:      map[string]string{},
		ServiceIPToNamespace:  map[string]string{},
	}

	repo := datastore.NewRepository(config.PostgresConfig{
		Host:     os.Getenv("POSTGRES_HOST"),
		Port:     os.Getenv("POSTGRES_PORT"),
		Username: os.Getenv("POSTGRES_USER"),
		Password: os.Getenv("POSTGRES_PASSWORD"),
		DBName:   os.Getenv("POSTGRES_DB"),
	})

	return &Aggregator{
		k8sChan:     k8sChan,
		crChan:      crChan,
		ebpfChan:    ebpfChan,
		clusterInfo: clusterInfo,
		repo:        repo,
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(a.clusterInfo.PidToSocketMap)
		},
	)
}

func (a *Aggregator) processk8s() {
	for data := range a.k8sChan {
		d := data.(k8s.K8sResourceMessage)
		// TODO: handle using resource uids instead of ip ?
		if d.ResourceType == k8s.POD {
			pod := d.Object.(*corev1.Pod)
			dtoPod := datastore.Pod{
				UID:       string(pod.UID),
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Image:     pod.Spec.Containers[0].Image,
				IP:        pod.Status.PodIP,
			}
			switch d.EventType {
			case k8s.ADD:
				a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
				a.clusterInfo.PodIPToNamespace[pod.Status.PodIP] = pod.Namespace
				err := a.repo.CreatePod(dtoPod)
				if err != nil {
					log.Logger.Error().Err(err).Msg("error on CreatePod call")
				}
			case k8s.UPDATE:
				a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
				a.clusterInfo.PodIPToNamespace[pod.Status.PodIP] = pod.Namespace
				err := a.repo.UpdatePod(dtoPod)
				if err != nil {
					log.Logger.Error().Err(err).Msg("error on UpdatePod call")
				}
			case k8s.DELETE:
				delete(a.clusterInfo.PodIPToPodUid, pod.Status.PodIP)
				delete(a.clusterInfo.PodIPToNamespace, pod.Status.PodIP)
				err := a.repo.DeletePod(dtoPod)
				if err != nil {
					log.Logger.Error().Err(err).Msg("error on DeletePod call")
				}
			}

		} else if d.ResourceType == k8s.SERVICE {
			service := d.Object.(*corev1.Service)
			dtoSvc := datastore.Service{
				UID:       string(service.UID),
				Name:      service.Name,
				Namespace: service.Namespace,
				Type:      string(service.Spec.Type),
				ClusterIP: service.Spec.ClusterIP,
			}

			switch d.EventType {
			case k8s.ADD:
				a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
				a.clusterInfo.ServiceIPToNamespace[service.Spec.ClusterIP] = service.Namespace
				err := a.repo.CreateService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			case k8s.UPDATE:
				a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
				a.clusterInfo.ServiceIPToNamespace[service.Spec.ClusterIP] = service.Namespace
				err := a.repo.UpdateService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			case k8s.DELETE:
				delete(a.clusterInfo.ServiceIPToServiceUid, service.Spec.ClusterIP)
				delete(a.clusterInfo.ServiceIPToNamespace, service.Spec.ClusterIP)
				err := a.repo.DeleteService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			}
		} else {
			log.Logger.Warn().Str("resourceType", d.ResourceType).Msg("Unknown resource type")
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
				m:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.m[d.Fd]
		sockMap.mu.RUnlock() // unlock for reading

		if !ok {
			skLine = &SocketLine{
				mu:     sync.RWMutex{},
				Values: make([]TimestampedSocket, 0),
			}
			sockMap.mu.Lock() // lock for writing
			sockMap.m[d.Fd] = skLine
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
			Msg("TCP_CLOSED event")

		var sockMap *SocketMap
		var ok bool
		if sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]; !ok {
			sockMap = &SocketMap{
				m:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
			return
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.m[d.Fd]
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
	var ok bool

	sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]
	if !ok {
		log.Logger.Info().Uint32("pid", d.Pid).Msg("error finding socket map")
		return
	}

	sockMap.mu.RLock() // lock for reading // !!lock-contention
	skLine, ok := sockMap.m[d.Fd]
	if !ok {
		log.Logger.Info().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Msg("error finding skLine")
		return
	}
	sockMap.mu.RUnlock() // unlock for reading

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

	retryCount := 10
	retryTime := 100 * time.Millisecond
	var skInfo *SockInfo
	var err error
	for skInfo, err = skLine.GetValue(d.WriteTimeNs); (err != nil || skInfo == nil) && retryCount > 0; {
		// early request, couldn't find socket info
		// wait and try again
		retryCount--
		time.Sleep(retryTime)
		retryTime = retryTime * 2 // exponential backoff
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("retrying getting socket info fro skLine")
	}

	if retryCount < 10 && skInfo != nil {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("found socket info with retry")
	}

	if err != nil || skInfo == nil {
		log.Logger.Error().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Str("method", d.Method).Uint32("status", d.Status).Str("protocol", d.Protocol).Str("payload", string(d.Payload[0:d.PayloadSize])).
			Msg("could not find !!socket info for skLine")
		return
	}

	// assuming successful request
	reqDto := datastore.Request{
		StartTime:  time.Now(),
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

	// find service info
	svcUid, ok := a.clusterInfo.ServiceIPToServiceUid[skInfo.Daddr]
	if ok {
		reqDto.ToUID = string(svcUid)
		reqDto.ToType = "service"
	}
	// if not found, it's 3rd party url or something else
	// ToUID and ToType will be empty

	reqDto.Completed = !d.Failed

	go a.repo.PersistRequest(reqDto)
	// err = a.repo.PersistRequest(reqDto)
	// if err != nil {
	// 	log.Logger.Error().Err(err).Msg("error persisting request")
	// }
}
