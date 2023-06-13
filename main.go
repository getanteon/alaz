package main

import (
	"alaz/cruntimes"
	"alaz/k8s"
	"alaz/log"
	"alaz/prog/tcp_state"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

func main() {

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

	// deploy ebpf collectors
	go tcp_state.Deploy()

	http.ListenAndServe(":8199", nil)
}
