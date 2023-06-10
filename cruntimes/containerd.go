package cruntimes

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	cri "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var defaultContainerdSock string = "/run/containerd/containerd.sock"
var containerTypeContainerdAnnotation string = "io.kubernetes.cri.container-type"

type ContainerdTracker struct {
	client         *containerd.Client
	imageCriClient cri.ImageServiceClient
}

// Direct information from containerd client has more information than
// getting it from containerd.ContainerService. LogDir, Pid, Volumes...

func NewContainerdTracker() (*ContainerdTracker, error) {
	ct := &ContainerdTracker{}
	// Connect to the containerd service
	unixSocket := "unix://" + strings.TrimPrefix(defaultContainerdSock, "unix://")

	// To list containerd namespaces
	// > ctr namespaces list
	// usually k8s.io and moby

	//  containerd.WithDefaultNamespace("k8s.io")
	client, err := containerd.New(defaultContainerdSock)
	if err != nil {
		return ct, err
	}
	ct.client = client

	conn, err := grpc.Dial(unixSocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		if errC := client.Close(); errC != nil {
			log.Fatal("Closing containerd connection", "error", errC)
		}
		log.Fatal("Could not dial grpc containerd socket", err)
	}

	ct.imageCriClient = cri.NewImageServiceClient(conn)
	return ct, nil
}

func (ct ContainerdTracker) ListAll(ctx context.Context) (KubernetesMetadata, error) {
	km := KubernetesMetadata{}

	nsList, err := ct.client.NamespaceService().List(ctx) // containerd namespaces
	if err != nil {
		return km, err
	}

	podInfos := []PodMetadata{}
	containerInfos := []ContainerMetadata{}

	for _, ns := range nsList {
		nsCtx := namespaces.WithNamespace(ctx, ns)
		// Get all containers in the containerd namespace
		cts, err := ct.client.Containers(nsCtx)
		if err != nil {
			return km, err
		}

		for _, container := range cts {
			// Get container spec
			task, err := container.Task(nsCtx, nil)
			if err != nil {
				// TODO: check error type
				fmt.Println(" no running task found")
				continue
			}

			pid := task.Pid()
			spec, err := task.Spec(nsCtx)
			if err != nil {
				return km, err
			}

			if isPod(spec.Annotations) {
				p := PodMetadata{
					PID:       pid,
					Name:      spec.Annotations["io.kubernetes.cri.sandbox-name"],
					Namespace: spec.Annotations["io.kubernetes.cri.sandbox-namespace"],
					PodID:     spec.Annotations["io.kubernetes.cri.sandbox-id"],
					LogDir:    spec.Annotations["io.kubernetes.cri.sandbox-log-directory"],
				}
				podInfos = append(podInfos, p)
			} else if isContainer(spec.Annotations) {
				// Container
				c := ContainerMetadata{
					PID:       pid,
					Name:      spec.Annotations["io.kubernetes.cri.container-name"],
					ImageName: spec.Annotations["io.kubernetes.cri.image-name"],
					PodID:     spec.Annotations["io.kubernetes.cri.sandbox-id"],
					PodName:   spec.Annotations["io.kubernetes.cri.sandbox-name"],
					Namespace: spec.Annotations["io.kubernetes.cri.sandbox-namespace"],
				}
				containerInfos = append(containerInfos, c)
			} else {
				fmt.Println("different type of container-type :", spec.Annotations["io.kubernetes.cri.container-type"])
			}
		}
	}

	km.ContainerMetadatas = containerInfos
	km.PodMetadatas = podInfos

	return km, nil
}

func isPod(annotations map[string]string) bool {
	return annotations[containerTypeContainerdAnnotation] == "sandbox"
}
func isContainer(annotations map[string]string) bool {
	return annotations[containerTypeContainerdAnnotation] == "container"
}
