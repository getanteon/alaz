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
	"alaz/ebpf/tcp_state"
	"alaz/log"
	"os"

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
type ClusterInfo struct {
	// TODO: If pod has more than one container, we need to differentiate
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	// IP:Port to IP:ort -> count
	TcpConnections map[string]map[string]uint32 `json:"tcpConnections"`
}

func NewAggregator(k8sChan <-chan interface{}, crChan <-chan interface{}, ebpfChan <-chan interface{}) *Aggregator {
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		TcpConnections:        map[string]map[string]uint32{},
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
		if d.EventType == k8s.ADD && d.ResourceType == k8s.POD {
			pod := d.Object.(*corev1.Pod)
			a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
			err := a.repo.CreatePod(datastore.Pod{
				UID:       string(pod.UID),
				Name:      pod.Name,
				Namespace: pod.Namespace,
				Image:     pod.Spec.Containers[0].Image,
				IP:        pod.Status.PodIP,
			})

			if err != nil {
				log.Logger.Debug().Err(err).Msg("error persisting pod data")
			}
		} else if d.EventType == k8s.ADD && d.ResourceType == k8s.SERVICE {
			service := d.Object.(*corev1.Service)
			a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
			err := a.repo.CreateService(datastore.Service{
				UID:       string(service.UID),
				Name:      service.Name,
				Namespace: service.Namespace,
				Type:      string(service.Spec.Type),
				ClusterIP: service.Spec.ClusterIP,
			})
			if err != nil {
				log.Logger.Debug().Err(err).Msg("error persisting service data")
			}
		} else if d.EventType == k8s.UPDATE && d.ResourceType == k8s.POD {
			// TODO: update pod
		} else if d.EventType == k8s.UPDATE && d.ResourceType == k8s.SERVICE {
			// TODO: update service
		} else if d.EventType == k8s.DELETE && d.ResourceType == k8s.POD {
			// TODO: delete pod
		} else if d.EventType == k8s.DELETE && d.ResourceType == k8s.SERVICE {
			// TODO: delete service
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
		d := data.(tcp_state.TcpConnectEvent)
		if _, ok := a.clusterInfo.TcpConnections[d.SAddr]; !ok {
			a.clusterInfo.TcpConnections[d.SAddr] = map[string]uint32{}
		}
		a.clusterInfo.TcpConnections[d.SAddr][d.DAddr]++
	}
}
