package cruntimes

// io.kubernetes.cri.container-type: "sandbox"
type PodMetadata struct {
	PID       uint32 `json:"pid"`
	Name      string `json:"name"`      // io.kubernetes.cri.sandbox-name
	Namespace string `json:"namespace"` // io.kubernetes.cri.sandbox-namespace
	PodID     string `json:"podID"`     // io.kubernetes.cri.sandbox-id
	LogDir    string `json:"logDir"`    // io.kubernetes.cri.sandbox-log-directory
}

// io.kubernetes.cri.container-type: "container"
type ContainerMetadata struct {
	PID       uint32 `json:"pid"`
	Name      string `json:"name"`      // io.kubernetes.cri.container-name
	ImageName string `json:"imageName"` // io.kubernetes.cri.image-name
	PodID     string `json:"podID"`     // io.kubernetes.cri.sandbox-id
	PodName   string `json:"podName"`   // io.kubernetes.cri.sandbox-name
	Namespace string `json:"namespace"` // io.kubernetes.cri.sandbox-namespace
}

type KubernetesMetadata struct {
	// Namespaces         []string
	PodMetadatas       []PodMetadata
	ContainerMetadatas []ContainerMetadata
}
