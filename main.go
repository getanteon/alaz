package main

import (
	"alaz/cruntimes"
	"alaz/k8s"
	"alaz/prog/tcp_state"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

func main() {
	// k8s collector
	k8sCollector, err := k8s.NewK8sCollector()
	if err != nil {
		panic(err)
	}
	go k8sCollector.Init()

	// container runtime collector
	ct, err := cruntimes.NewContainerdTracker()
	if err != nil {
		log.Fatal(err)
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	km, err := ct.ListAll(ctx)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/cr-pods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.PodMetadatas)
	})

	http.HandleFunc("/cr-containers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.ContainerMetadatas)
	})

	fmt.Println("listen on 8199")

	// deploy ebpf collectors
	go tcp_state.Deploy()

	http.ListenAndServe(":8199", nil)
}
