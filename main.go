package main

import (
	"alaz/aggregator"
	"alaz/cruntimes"
	"alaz/ebpf"
	"alaz/k8s"
	"os"
	"runtime/trace"

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
	a.Init()
	a.Run()
	a.AdvertisePidSockMap()

	if os.Getenv("TRACE_ENABLED") == "true" {
		directoryPath := "/mnt/data/"

		// Create the directory if it doesn't exist
		if err := os.MkdirAll(directoryPath, os.ModePerm); err != nil {
			log.Logger.Fatal().Msgf("failed to create directory: %v", err)
			return
		}

		traceFile, err := os.Create("/mnt/data/trace.out")
		if err != nil {
			log.Logger.Fatal().Msgf("failed to create trace output file: %v", err)
		}
		defer func() {
			if err := traceFile.Close(); err != nil {
				log.Logger.Fatal().Msgf("failed to close trace file: %v", err)
			}
		}()

		if err := trace.Start(traceFile); err != nil {
			log.Logger.Fatal().Msgf("failed to start trace: %v", err)
		}
	}
	// defer trace.Stop()

	http.HandleFunc("/stop-trace", func(w http.ResponseWriter, r *http.Request) {
		trace.Stop()
	})

	log.Logger.Info().Msg("listen on 8181")
	http.ListenAndServe(":8181", nil)
}

func crCollector() {
	ct, err := cruntimes.NewContainerdTracker()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create containerd tracker")
	}

	http.HandleFunc("/cr-pods", func(w http.ResponseWriter, r *http.Request) {
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		km, err := ct.ListAll(ctx)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.PodMetadatas)
	})

	http.HandleFunc("/cr-containers", func(w http.ResponseWriter, r *http.Request) {
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		km, err := ct.ListAll(ctx)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(km.ContainerMetadatas)
	})
}
