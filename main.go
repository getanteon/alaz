package main

import (
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/config"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/k8s"

	"context"

	"github.com/ddosify/alaz/log"

	"net/http"
	_ "net/http/pprof"
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
	if os.Getenv("K8S_COLLECTOR_ENABLED") != "false" {
		// k8s collector
		var err error
		k8sCollector, err = k8s.NewK8sCollector(ctx)
		if err != nil {
			panic(err)
		}
		go k8sCollector.Init(kubeEvents)
	}

	ebpfEnabled, _ := strconv.ParseBool(os.Getenv("EBPF_ENABLED"))
	metricsEnabled, _ := strconv.ParseBool(os.Getenv("METRICS_ENABLED"))

	// datastore backend
	dsBackend := datastore.NewBackendDS(ctx, config.BackendConfig{
		Host:                  os.Getenv("BACKEND_HOST"),
		Port:                  os.Getenv("BACKEND_PORT"),
		MetricsExport:         metricsEnabled,
		MetricsExportInterval: 10,
	})
	go dsBackend.SendHealthCheck(ebpfEnabled, metricsEnabled)

	// deploy ebpf programs
	var ec *ebpf.EbpfCollector
	if ebpfEnabled {
		ec = ebpf.NewEbpfCollector(ctx)
		go ec.Deploy()

		a := aggregator.NewAggregator(ctx, kubeEvents, ec, dsBackend)
		a.Run()
	}

	go http.ListenAndServe(":8181", nil)

	<-k8sCollector.Done()
	log.Logger.Info().Msg("k8sCollector done")

	<-ec.Done()
	log.Logger.Info().Msg("ebpfCollector done")

	log.Logger.Info().Msg("alaz exiting...")
}
