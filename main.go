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
	var k8sCollector *k8s.K8sCollector
	kubeEvents := make(chan interface{}, 1000)
	if os.Getenv("K8S_COLLECTOR_ENABLED") == "true" {
		// k8s collector
		var err error
		k8sCollector, err = k8s.NewK8sCollector()
		if err != nil {
			panic(err)
		}
		go k8sCollector.Init(kubeEvents)
	}

	// container runtime collector
	if os.Getenv("CR_COLLECTOR_ENABLED") == "true" {
		go crCollector()
	}

	// deploy ebpf programs
	if os.Getenv("EBPF_ENABLED") == "true" {
		go ebpf.Deploy()
	}

	a := aggregator.NewAggregator(kubeEvents, nil, ebpf.EbpfEvents)
	a.Run()
	a.AdvertisePidSockMap()

	log.Logger.Info().Msg("listen on 8181")
	http.ListenAndServe(":8181", nil)
}

func crCollector() {
	ct, err := cruntimes.NewContainerdTracker()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create containerd tracker")
	}
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	http.HandleFunc("/cr-pods", func(w http.ResponseWriter, r *http.Request) {
		km, err := ct.ListAll(ctx)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.PodMetadatas)
	})

	http.HandleFunc("/cr-containers", func(w http.ResponseWriter, r *http.Request) {
		km, err := ct.ListAll(ctx)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.ContainerMetadatas)
	})
}
