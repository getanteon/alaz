package cruntimes

import (
	"context"
	"fmt"
	"log"

	"github.com/containerd/containerd"
	"github.com/kylelemons/godebug/pretty"
)

// io.kubernetes.cri.container-type: "sandbox"
type Pod struct {
	PID       uint32
	Name      string // io.kubernetes.cri.sandbox-name
	Namespace string // io.kubernetes.cri.sandbox-namespace
	PodID     string // io.kubernetes.cri.sandbox-id
	LogDir    string // io.kubernetes.cri.sandbox-log-directory
}

// io.kubernetes.cri.container-type: "container"
type ContainerInfo struct {
	PID       uint32
	Name      string // io.kubernetes.cri.container-name
	ImageName string // io.kubernetes.cri.image-name
	PodID     string // io.kubernetes.cri.sandbox-id
	PodName   string // io.kubernetes.cri.sandbox-name
	Namespace string // io.kubernetes.cri.sandbox-namespace
}

func ShowAllContainerd() {
	// Connect to the containerd service

	client, err := containerd.New("/run/containerd/containerd.sock", containerd.WithDefaultNamespace("k8s.io"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// // Set the context with the default namespace
	// ctx := namespaces.WithNamespace(context.Background(),)

	// Get all containers
	// only running ones I think ?
	// makine ustundeki containerlari gosterdi, minikube icindekileri gostermedi, deploy edip bide bu socketi mountlamak lazim
	containers, err := client.Containers(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	// Print container information
	fmt.Println("Running Containers:")

	podInfos := []Pod{}
	containerInfos := []ContainerInfo{}

	for _, container := range containers {
		// If HostName is not empty and io.kubernetes.cri.container-type: "sandbox" --> pod
		// If HostName is empty and io.kubernetes.cri.container-type: "container" --> container

		// id in container runtime
		// pretty.Print("containerID: %s\n", container.ID())

		task, err := container.Task(context.TODO(), nil)
		if err != nil {
			fmt.Println("could not create task", err)
		} else {
			pid := task.Pid()

			// fmt.Printf("PID: %d\n", pid)
			spec, err := task.Spec(context.TODO())
			if err != nil {
				fmt.Println("could not get spec")
			}

			if spec.Annotations["io.kubernetes.cri.container-type"] == "sandbox" {
				// Pod
				p := Pod{
					PID:       pid,
					Name:      spec.Hostname,
					Namespace: spec.Annotations["io.kubernetes.cri.sandbox-namespace"],
					PodID:     spec.Annotations["io.kubernetes.cri.sandbox-id"],
					LogDir:    spec.Annotations["io.kubernetes.cri.sandbox-log-directory"],
				}
				podInfos = append(podInfos, p)
			} else if spec.Annotations["io.kubernetes.cri.container-type"] == "container" {
				// Container
				c := ContainerInfo{
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

			// pretty.Print(spec)
		}
		fmt.Println("-------------------")
	}

	fmt.Println("------------POD_INFOS-------------")
	pretty.Print(podInfos)

	fmt.Println("------------CONTAINER_INFOS-------------")
	pretty.Print(containerInfos)
}
