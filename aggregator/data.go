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
	"os"
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

type SocketMap map[uint64]SockInfo // fd -> SockInfo

type ClusterInfo struct {
	// TODO: If pod has more than one container, we need to differentiate
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	// Pid -> SocketMap
	// pid -> fd -> {saddr, sport, daddr, dport}
	PidToSocketMap map[uint32]SocketMap `json:"pidToSocketMap"`
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

type ProcessConnectionMap map[string]SocketMap // Map to store {pid} - > SocketInfo

func NewAggregator(k8sChan <-chan interface{}, crChan <-chan interface{}, ebpfChan <-chan interface{}) *Aggregator {
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		PidToSocketMap:        map[uint32]SocketMap{},
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

func (a *Aggregator) processk8s() {
	for data := range a.k8sChan {
		d := data.(k8s.K8sResourceMessage)

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
				err := a.repo.CreatePod(dtoPod)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error on CreatePod call")
				}
			case k8s.UPDATE:
				a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
				err := a.repo.UpdatePod(dtoPod)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error on UpdatePod call")
				}
			case k8s.DELETE:
				delete(a.clusterInfo.PodIPToPodUid, pod.Status.PodIP)
				err := a.repo.DeletePod(dtoPod)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error on DeletePod call")
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
				err := a.repo.CreateService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			case k8s.UPDATE:
				a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
				err := a.repo.UpdateService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			case k8s.DELETE:
				delete(a.clusterInfo.ServiceIPToServiceUid, service.Spec.ClusterIP)
				err := a.repo.DeleteService(dtoSvc)
				if err != nil {
					log.Logger.Debug().Err(err).Msg("error persisting service data")
				}
			}
		} else {
			log.Logger.Debug().Str("resourceType", d.ResourceType).Msg("Unknown resource type")
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
			log.Logger.Debug().Msg("error casting ebpf event")
			continue
		}
		switch bpfEvent.Type() {
		case tcp_state.TCP_CONNECT_EVENT:
			a.processTcpConnect(data)
		// TODO: TCP_CLOSE
		case l7_req.L7_EVENT:
			a.processL7(data)
		}
	}
}

func (a *Aggregator) processTcpConnect(data interface{}) {
	d := data.(tcp_state.TcpConnectEvent)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {
		// {pid,fd} -> SockInfo
		if _, ok := a.clusterInfo.PidToSocketMap[d.Pid]; !ok {
			a.clusterInfo.PidToSocketMap[d.Pid] = SocketMap{}
		}
		a.clusterInfo.PidToSocketMap[d.Pid][d.Fd] = SockInfo{
			Pid:   d.Pid,
			Fd:    d.Fd,
			Saddr: d.SAddr,
			Sport: d.SPort,
			Daddr: d.DAddr,
			Dport: d.DPort,
		}

		// TODO: persist

	} else if d.Type_ == tcp_state.EVENT_TCP_CLOSED {
		// remove from map
		delete(a.clusterInfo.PidToSocketMap[d.Pid], d.Fd)
		// TODO: persist
	}

}

func (a *Aggregator) processL7(data interface{}) {
	d := data.(l7_req.L7Event)
	// find socket info

	skInfo, ok := a.clusterInfo.PidToSocketMap[d.Pid][d.Fd]
	if !ok {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Msg("error finding socket info")
		return
	}

	// assuming successful request
	// TODO: handle failed request, timeout case ?

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

	// find pod info
	podUid, ok := a.clusterInfo.PodIPToPodUid[skInfo.Saddr]
	if !ok {
		log.Logger.Debug().Str("podIP", skInfo.Saddr).Msg("error finding pod info")
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

	log.Logger.Debug().Int("pid", int(d.Pid)).
		Uint64("fd", d.Fd).
		Str("saddr", skInfo.Saddr).
		Uint16("sport", skInfo.Sport).
		Str("daddr", skInfo.Daddr).
		Uint16("dport", skInfo.Dport).
		Str("method", d.Method).
		Uint64("duration", d.Duration).
		Str("protocol", d.Protocol).
		Uint32("status", d.Status).
		Str("payload", string(d.Payload[:])).
		Msg("l7 event success on aggregator")

	err := a.repo.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Debug().Err(err).Msg("error persisting request")
	}
}
