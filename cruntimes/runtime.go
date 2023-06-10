package cruntimes

// io.kubernetes.cri.container-type: "sandbox"
type PodMetadata struct {
	PID       uint32
	Name      string // io.kubernetes.cri.sandbox-name
	Namespace string // io.kubernetes.cri.sandbox-namespace
	PodID     string // io.kubernetes.cri.sandbox-id
	LogDir    string // io.kubernetes.cri.sandbox-log-directory
}

// io.kubernetes.cri.container-type: "container"
type ContainerMetadata struct {
	PID       uint32
	Name      string // io.kubernetes.cri.container-name
	ImageName string // io.kubernetes.cri.image-name
	PodID     string // io.kubernetes.cri.sandbox-id
	PodName   string // io.kubernetes.cri.sandbox-name
	Namespace string // io.kubernetes.cri.sandbox-namespace
}

type KubernetesMetadata struct {
	// Namespaces         []string
	PodMetadatas       []PodMetadata
	ContainerMetadatas []ContainerMetadata
}
