package cruntimes

import (
	"context"
	"fmt"
	"log"

	"github.com/containerd/containerd"
	"github.com/kylelemons/godebug/pretty"
)

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
	// TODO: moby namespace bak ...
	for _, container := range containers {

		pretty.Print("containerID: %s\n", container.ID())
		// fmt.Printf("ID: %s\n", container.ID())
		task, err := container.Task(context.TODO(), nil)
		if err != nil {
			fmt.Println("could not create task", err)
		} else {
			pretty.Print(task)

			pid := task.Pid()
			fmt.Printf("PID: %d\n", pid)
			spec, err := task.Spec(context.TODO())
			if err != nil {
				fmt.Println("could not get spec")
			}

			pretty.Print(spec)

			// fmt.Println("annotations", spec.Annotations)
			// fmt.Println("domainName", spec.Domainname)
			// fmt.Println("hostName", spec.Hostname)
			// fmt.Println("process", spec.Process)
			// fmt.Println("process-cmd", spec.Process.CommandLine)

		}
		// c, err := client.ContainerService().Get(ctx, container.ID())
		// if err != nil {
		// 	fmt.Println(err)
		// } else {
		// 	// fmt.Printf("%+v\n", c)
		// 	// fmt.Printf("Image: %s\n", c.Image)
		// }
		// status, err := container.Status(ctx)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Printf("Status: %s\n", status.Status)
		fmt.Println("-------------------")
	}
}
