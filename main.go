package main

import (
	"alaz/aggregator"
	"alaz/ebpf"
	"alaz/k8s"
	"os"
	"os/signal"
	"syscall"

	"alaz/log"
	"context"
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

		a := aggregator.NewAggregator(ctx, kubeEvents, nil, ec.EbpfEvents())
		a.Run()
	}

	<-k8sCollector.Done()
	log.Logger.Info().Msg("k8sCollector done")

	<-ec.Done()
	log.Logger.Info().Msg("ebpfCollector done")

	log.Logger.Info().Msg("alaz exiting...")
}
