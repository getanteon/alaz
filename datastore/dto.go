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
		Name     string `json:"name"`
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

type StatefulSet struct {
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
	Name     string `json:"name"`
}

// Subsets
type Address struct {
	IPs   []AddressIP   `json:"ips"`
	Ports []AddressPort `json:"ports"`
}

type Container struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	PodUID    string `json:"pod"` // Pod UID
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type AliveConnection struct {
	CheckTime int64 // connection is alive at this time, ms
	FromIP    string
	FromType  string
	FromUID   string
	FromPort  uint16
	ToIP      string
	ToType    string
	ToUID     string
	ToPort    uint16
}

type DirectionalEvent interface {
	SetFromUID(string)
	SetFromIP(string)
	SetFromType(string)
	SetFromPort(uint16)

	SetToUID(string)
	SetToIP(string)
	SetToType(string)
	SetToPort(uint16)

	ReverseDirection()
}

type KafkaEvent struct {
	StartTime int64
	Latency   uint64 // in ns
	FromIP    string
	FromType  string
	FromUID   string
	FromPort  uint16
	ToIP      string
	ToType    string
	ToUID     string
	ToPort    uint16
	Topic     string
	Partition uint32
	Key       string
	Value     string
	Type      string // PUBLISH or CONSUME
	Tls       bool
	// dist tracing disabled by default temporarily
	// Tid       uint32
	// Seq       uint32
}

func (ke *KafkaEvent) SetFromUID(uid string) {
	ke.FromUID = uid
}
func (ke *KafkaEvent) SetFromIP(ip string) {
	ke.FromIP = ip
}
func (ke *KafkaEvent) SetFromType(typ string) {
	ke.FromType = typ
}
func (ke *KafkaEvent) SetFromPort(port uint16) {
	ke.FromPort = port
}

func (ke *KafkaEvent) SetToUID(uid string) {
	ke.ToUID = uid
}
func (ke *KafkaEvent) SetToIP(ip string) {
	ke.ToIP = ip
}
func (ke *KafkaEvent) SetToType(typ string) {
	ke.ToType = typ
}
func (ke *KafkaEvent) SetToPort(port uint16) {
	ke.ToPort = port
}

func (req *KafkaEvent) ReverseDirection() {
	req.FromIP, req.ToIP = req.ToIP, req.FromIP
	req.FromPort, req.ToPort = req.ToPort, req.FromPort
	req.FromUID, req.ToUID = req.ToUID, req.FromUID
	req.FromType, req.ToType = req.ToType, req.FromType
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
	Tls        bool
	Completed  bool
	StatusCode uint32
	FailReason string
	Method     string
	Path       string
	// dist tracing disabled by default temporarily
	// Tid        uint32
	// Seq        uint32
}

func (r *Request) SetFromUID(uid string) {
	r.FromUID = uid
}
func (r *Request) SetFromIP(ip string) {
	r.FromIP = ip
}
func (r *Request) SetFromType(typ string) {
	r.FromType = typ
}
func (r *Request) SetFromPort(port uint16) {
	r.FromPort = port
}

func (r *Request) SetToUID(uid string) {
	r.ToUID = uid
}
func (r *Request) SetToIP(ip string) {
	r.ToIP = ip
}
func (r *Request) SetToType(typ string) {
	r.ToType = typ
}
func (r *Request) SetToPort(port uint16) {
	r.ToPort = port
}

func (req *Request) ReverseDirection() {
	req.FromIP, req.ToIP = req.ToIP, req.FromIP
	req.FromPort, req.ToPort = req.ToPort, req.FromPort
	req.FromUID, req.ToUID = req.ToUID, req.FromUID
	req.FromType, req.ToType = req.ToType, req.FromType
}

type BackendResponse struct {
	Msg    string `json:"msg"`
	Errors []struct {
		EventNum int         `json:"event_num"`
		Event    interface{} `json:"event"`
		Error    string      `json:"error"`
	} `json:"errors"`
}

type ReqBackendReponse struct {
	Msg    string `json:"msg"`
	Errors []struct {
		EventNum int         `json:"request_num"`
		Event    interface{} `json:"request"`
		Error    string      `json:"errors"`
	} `json:"errors"`
}
