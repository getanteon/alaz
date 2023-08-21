package main

import (
	"alaz/aggregator"
	"alaz/ebpf"
	"alaz/k8s"
	"os"
	"os/signal"
	"runtime/trace"
	"syscall"

	"alaz/log"
	"context"
	"net/http"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	go func() {
		<-c
		signal.Stop(c)
		cancel()
	}()

	var k8sCollector *k8s.K8sCollector
	kubeEvents := make(chan interface{}, 1000)
	if os.Getenv("K8S_COLLECTOR_ENABLED") == "true" {
		// k8s collector
		var err error
		k8sCollector, err = k8s.NewK8sCollector(ctx)
		if err != nil {
			panic(err)
		}
		go k8sCollector.Init(kubeEvents)
	}

	// deploy ebpf programs
	var ec *ebpf.EbpfCollector
	if os.Getenv("EBPF_ENABLED") != "false" {
		ec = ebpf.NewEbpfCollector(ctx)
		go ec.Deploy()

		a := aggregator.NewAggregator(kubeEvents, nil, ec.EbpfEvents())
		a.Run()
		a.AdvertisePidSockMap()
	}

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

	http.HandleFunc("/stop-trace", func(w http.ResponseWriter, r *http.Request) {
		trace.Stop()
	})

	go func() {
		log.Logger.Info().Msg("listen on 8181")
		http.ListenAndServe(":8181", nil)
	}()

	<-k8sCollector.Done()
	log.Logger.Info().Msg("k8sCollector done")

	<-ec.Done()
	log.Logger.Info().Msg("ebpfCollector done")

	log.Logger.Info().Msg("alaz exiting...")
}
