package main

import (
	"alaz/aggregator"
	"alaz/cruntimes"
	"alaz/ebpf"
	"alaz/k8s"
	"os"

	"alaz/log"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func main() {

	// var k8sCollector *k8s.K8sCollector
	if os.Getenv("K8S_COLLECTOR_ENABLED") == "true" {
		// k8s collector
		k8sCollector, err := k8s.NewK8sCollector()
		if err != nil {
			panic(err)
		}
		go k8sCollector.Init()
	}

	// container runtime collector
	ct, err := cruntimes.NewContainerdTracker()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create containerd tracker")
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	km, err := ct.ListAll(ctx)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to get containerd metadata")
	}

	http.HandleFunc("/cr-pods", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.PodMetadatas)
	})

	http.HandleFunc("/cr-containers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.ContainerMetadatas)
	})

	log.Logger.Info().Msg("listen on 8199")

	// deploy ebpf programs
	go ebpf.Deploy()

	a := aggregator.NewAggregator(nil, nil, ebpf.EbpfEvents)
	a.Run()

	http.HandleFunc("/service-map", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a.Advertise())
	})

	http.ListenAndServe(":8198", nil)
}
