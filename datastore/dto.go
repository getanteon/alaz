package datastore

type Pod struct {
	UID       string // Pod UID
	Name      string // Pod Name
	Namespace string // Namespace
	Image     string // Main container image
	IP        string // Pod IP
	OwnerType string // ReplicaSet or nil
	OwnerID   string // ReplicaSet UID
	OwnerName string // ReplicaSet Name
}

type Service struct {
	UID        string
	Name       string
	Namespace  string
	Type       string
	ClusterIP  string
	ClusterIPs []string
	Ports      []struct {
		Src      int32  `json:"src"`
		Dest     int32  `json:"dest"`
		Protocol string `json:"protocol"`
	}
}

type ReplicaSet struct {
	UID       string // ReplicaSet UID
	Name      string // ReplicaSet Name
	Namespace string // Namespace
	OwnerType string // Deployment or nil
	OwnerID   string // Deployment UID
	OwnerName string // Deployment Name
	Replicas  int32  // Number of replicas
}

type DaemonSet struct {
	UID       string // ReplicaSet UID
	Name      string // ReplicaSet Name
	Namespace string // Namespace
}

type Deployment struct {
	UID       string // Deployment UID
	Name      string // Deployment Name
	Namespace string // Namespace
	Replicas  int32  // Number of replicas
}

type Endpoints struct {
	UID       string // Endpoints UID
	Name      string // Endpoints Name
	Namespace string // Namespace
	Addresses []Address
}

type AddressIP struct {
	Type      string `json:"type"` // pod or external
	ID        string `json:"id"`   // Pod UID or empty
	Name      string `json:"name"`
	Namespace string `json:"namespace"` // Pod Namespace or empty
	IP        string `json:"ip"`        // Pod IP or external IP
}

type AddressPort struct {
	Port     int32  `json:"port"`     // Port number
	Protocol string `json:"protocol"` // TCP or UDP
}

// Subsets
type Address struct {
	IPs   []AddressIP   `json:"ips"`
	Ports []AddressPort `json:"ports"`
}

type Container struct {
	UID       string `json:"uid"` // TODO: remove
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	PodUID    string `json:"pod"` // Pod UID
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type Request struct {
	StartTime  int64
	Latency    uint64 // in ns
	FromIP     string
	FromType   string
	FromUID    string
	FromPort   uint16
	ToIP       string
	ToType     string
	ToUID      string
	ToPort     uint16
	Protocol   string
	Completed  bool
	StatusCode uint32
	FailReason string
	Method     string
	Path       string
}
