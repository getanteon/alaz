package aggregator

// aggregate data from different sources
// 1. k8s
// 2. containerd
// 3. ebpf
// 4. cgroup (TODO)
// 5. docker (TODO)

// Path: aggregator/data.go

import (
	"alaz/ebpf/tcp_state"
	"alaz/graph"
	"alaz/k8s"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type Aggregator struct {
	k8sChan  <-chan interface{}
	crChan   <-chan interface{}
	ebpfChan <-chan interface{}

	serviceMap *ServiceMap
}

type ServiceMap struct {
	// TODO: add port information

	PodNamesWithNamespace map[string]string    `json:"podNamesWithNamespace"`
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	PodIPToPodName        map[string]string    `json:"podIPToPodName"`

	ServiceNamesWithNamespace map[string]string    `json:"serviceNamesWithNamespace"`
	ServiceIPToServiceName    map[string]string    `json:"serviceIPToServiceName"`
	ServiceIPToServiceUid     map[string]types.UID `json:"serviceIPToServiceUid"`
	// IP to IP -> count
	TcpConnections map[string]map[string]uint32 `json:"tcpConnections"`
}

func (a *Aggregator) Advertise() ServiceMap {
	// -pod and -service suffixes are for now, to differentiate between
	podNames := func() []string {
		var podNames []string
		for _, v := range a.serviceMap.PodIPToPodName {
			podNames = append(podNames, v+"-pod")
		}
		return podNames
	}()
	serviceNames := func() []string {
		var serviceNames []string
		for _, v := range a.serviceMap.ServiceIPToServiceName {
			serviceNames = append(serviceNames, v+"-svc")
		}
		return serviceNames
	}()

	fmt.Println("podNames", podNames)
	fmt.Println("serviceNames", serviceNames)
	graph.AddNodes(append(podNames, serviceNames...)...)
	for from, toMap := range a.serviceMap.TcpConnections {
		for to, count := range toMap {

			// find name from ip
			var fromName, toName string
			fromName, ok := a.serviceMap.PodIPToPodName[from]
			if !ok {
				fromName, ok = a.serviceMap.ServiceIPToServiceName[from]
				if !ok {
					fmt.Println("from ip not found", from)
				} else {
					fromName = fromName + "-svc"
				}
			} else {
				fromName = fromName + "-pod"
			}

			toName, ok = a.serviceMap.PodIPToPodName[to]
			if !ok {
				toName = a.serviceMap.ServiceIPToServiceName[to]
				if !ok {
					fmt.Println("to ip not found", to)
				} else {
					toName = toName + "-svc"
				}
			} else {
				toName = toName + "-pod"
			}

			graph.AddEdge(fromName, toName, count)
		}
	}

	return *a.serviceMap
}

func NewAggregator(k8sChan <-chan interface{}, crChan <-chan interface{}, ebpfChan <-chan interface{}) *Aggregator {
	serviceMap := &ServiceMap{
		PodNamesWithNamespace:     map[string]string{},
		PodIPToPodUid:             map[string]types.UID{},
		PodIPToPodName:            map[string]string{},
		ServiceNamesWithNamespace: map[string]string{},
		ServiceIPToServiceName:    map[string]string{},
		ServiceIPToServiceUid:     map[string]types.UID{},
		TcpConnections:            map[string]map[string]uint32{},
	}
	return &Aggregator{
		k8sChan:    k8sChan,
		crChan:     crChan,
		ebpfChan:   ebpfChan,
		serviceMap: serviceMap,
	}
}

func (a *Aggregator) Run() {
	go a.processk8s()
	go a.processCR()
	go a.processEbpf()
}

func (a *Aggregator) processk8s() {
	for data := range a.k8sChan {
		// K8sResourceMessage
		d := data.(k8s.K8sResourceMessage)
		// TODO: add more types
		// TODO: check event types, delete/update, assume add for now
		switch d.ResourceType {
		case k8s.Pod:
			pod := d.Object.(*corev1.Pod)
			a.serviceMap.PodIPToPodUid[pod.Status.PodIP] = pod.UID
			a.serviceMap.PodIPToPodName[pod.Status.PodIP] = pod.Name
		case k8s.Service:
			service := d.Object.(*corev1.Service)
			a.serviceMap.ServiceIPToServiceName[service.Spec.ClusterIP] = service.Name
			a.serviceMap.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
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
		if _, ok := a.serviceMap.TcpConnections[d.SAddr]; !ok {
			a.serviceMap.TcpConnections[d.SAddr] = map[string]uint32{}
		}
		a.serviceMap.TcpConnections[d.SAddr][d.DAddr]++
	}
}
