package datastore

type PodPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	IP        string `json:"ip"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type SvcPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
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

type ReplicaSetPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type DeploymentPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
}

type EndpointsPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string    `json:"uid"`
	EventType string    `json:"event_type"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Service   string    `json:"service"`
	Addresses []Address `json:"addresses"`
}

type ContainerPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
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
// 11) Response Code
// 12) ??
// 13) Method
// 14) Path
type ReqInfo [15]interface{}

type RequestsPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	Requests []*ReqInfo `json:"requests"`
}
