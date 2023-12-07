package datastore

type Metadata struct {
	MonitoringID   string `json:"monitoring_id"`
	IdempotencyKey string `json:"idempotency_key"`
	NodeID         string `json:"node_id"`
	AlazVersion    string `json:"alaz_version"`
}

type HealthCheckPayload struct {
	Metadata Metadata `json:"metadata"`
	Info     struct {
		EbpfEnabled    bool `json:"ebpf"`
		MetricsEnabled bool `json:"metrics"`
	} `json:"alaz_info"`
	Telemetry struct {
		KernelVersion string `json:"kernel_version"`
		K8sVersion    string `json:"k8s_version"`
		CloudProvider string `json:"cloud_provider"`
	} `json:"telemetry"`
}

type EventPayload struct {
	Metadata Metadata      `json:"metadata"`
	Events   []interface{} `json:"events"`
}

type PodEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	IP        string `json:"ip"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type SvcEvent struct {
	UID        string   `json:"uid"`
	EventType  string   `json:"event_type"`
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Type       string   `json:"type"`
	ClusterIPs []string `json:"cluster_ips"`
	Ports      []struct {
		Src      int32  `json:"src"`
		Dest     int32  `json:"dest"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type RsEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type DsEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type DepEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
}

type EpEvent struct {
	UID       string    `json:"uid"`
	EventType string    `json:"event_type"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Addresses []Address `json:"addresses"`
}

type ContainerEvent struct {
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

// 0) StartTime
// 1) Latency
// 2) Source IP
// 3) Source Type
// 4) Source ID
// 5) Source Port
// 6) Destination IP
// 7) Destination Type
// 8) Destination ID
// 9) Destination Port
// 10) Protocol
// 11) Response Status Code
// 12) Fail Reason // TODO: not used yet
// 13) Method
// 14) Path
// 15) Encrypted (bool)
type ReqInfo [16]interface{}

type RequestsPayload struct {
	Metadata Metadata   `json:"metadata"`
	Requests []*ReqInfo `json:"requests"`
}

func convertPodToPodEvent(pod Pod, eventType string) PodEvent {
	return PodEvent{
		UID:       pod.UID,
		EventType: eventType,
		Name:      pod.Name,
		Namespace: pod.Namespace,
		IP:        pod.IP,
		OwnerType: pod.OwnerType,
		OwnerName: pod.OwnerName,
		OwnerID:   pod.OwnerID,
	}
}

func convertSvcToSvcEvent(service Service, eventType string) SvcEvent {
	return SvcEvent{
		UID:        service.UID,
		EventType:  eventType,
		Name:       service.Name,
		Namespace:  service.Namespace,
		Type:       service.Type,
		ClusterIPs: service.ClusterIPs,
		Ports:      service.Ports,
	}
}

func convertRsToRsEvent(rs ReplicaSet, eventType string) RsEvent {
	return RsEvent{
		UID:       rs.UID,
		EventType: eventType,
		Name:      rs.Name,
		Namespace: rs.Namespace,
		Replicas:  rs.Replicas,
		OwnerType: rs.OwnerType,
		OwnerName: rs.OwnerName,
		OwnerID:   rs.OwnerID,
	}
}

func convertDsToDsEvent(ds DaemonSet, eventType string) DsEvent {
	return DsEvent{
		UID:       ds.UID,
		EventType: eventType,
		Name:      ds.Name,
		Namespace: ds.Namespace,
	}
}

func convertDepToDepEvent(d Deployment, eventType string) DepEvent {
	return DepEvent{
		UID:       d.UID,
		EventType: eventType,
		Name:      d.Name,
		Namespace: d.Namespace,
		Replicas:  d.Replicas,
	}
}

func convertEpToEpEvent(ep Endpoints, eventType string) EpEvent {
	return EpEvent{
		UID:       ep.UID,
		EventType: eventType,
		Name:      ep.Name,
		Namespace: ep.Namespace,
		Addresses: ep.Addresses,
	}
}

func convertContainerToContainerEvent(c Container, eventType string) ContainerEvent {
	return ContainerEvent{
		EventType: eventType,
		Name:      c.Name,
		Namespace: c.Namespace,
		Pod:       c.PodUID,
		Image:     c.Image,
		Ports:     c.Ports,
	}
}
