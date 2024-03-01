package main

import (
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/config"
	"github.com/ddosify/alaz/cri"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/k8s"

	"context"

	"github.com/ddosify/alaz/log"

	"net/http"
	_ "net/http/pprof"
)

func main() {
	debug.SetGCPercent(80)
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
	var k8sVersion string

	var k8sCollectorEnabled bool = true
	k8sEnabled, err := strconv.ParseBool(os.Getenv("K8S_COLLECTOR_ENABLED"))
	if err == nil && !k8sEnabled {
		k8sCollectorEnabled = false
	}

	if k8sCollectorEnabled {
		// k8s collector
		var err error
		k8sCollector, err = k8s.NewK8sCollector(ctx)
		if err != nil {
			panic(err)
		}
		k8sVersion = k8sCollector.GetK8sVersion()
		go k8sCollector.Init(kubeEvents)
	}

	// EBPF_ENABLED changed to SERVICE_MAP_ENABLED
	// for backwards compatibility
	ebpfEnabled, err := strconv.ParseBool(os.Getenv("SERVICE_MAP_ENABLED"))
	if err != nil {
		// if SERVICE_MAP_ENABLED not given, check EBPF_ENABLED
		ebpfEnabled, _ = strconv.ParseBool(os.Getenv("EBPF_ENABLED"))
	}

	metricsEnabled, _ := strconv.ParseBool(os.Getenv("METRICS_ENABLED"))
	distTracingEnabled, _ := strconv.ParseBool(os.Getenv("DIST_TRACING_ENABLED"))
	logsEnabled, _ := strconv.ParseBool(os.Getenv("LOGS_ENABLED"))

	// datastore backend
	dsBackend := datastore.NewBackendDS(ctx, config.BackendDSConfig{
		Host:                  os.Getenv("BACKEND_HOST"),
		MetricsExport:         metricsEnabled,
		MetricsExportInterval: 10,
		ReqBufferSize:         40000, // TODO: get from a conf file
		ConnBufferSize:        1000,  // TODO: get from a conf file
	})
	go dsBackend.SendHealthCheck(ebpfEnabled, metricsEnabled, distTracingEnabled, k8sVersion)

	// deploy ebpf programs
	var ec *ebpf.EbpfCollector
	if ebpfEnabled {
		ec = ebpf.NewEbpfCollector(ctx)

		a := aggregator.NewAggregator(ctx, kubeEvents, ec.EbpfEvents(), ec.EbpfProcEvents(), ec.EbpfTcpEvents(), ec.TlsAttachQueue(), dsBackend)
		a.Run()

		ec.Init()
		go ec.ListenEvents()
	}

	var ct *cri.CRITool
	if logsEnabled {
		ct, err = cri.NewCRITool(ctx)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to create cri tool")
		} else {
			go func() {
				err := ct.StreamLogs()
				if err != nil {
					log.Logger.Error().Err(err).Msg("failed to stream logs")
				}
			}()
		}
	}

	go http.ListenAndServe(":8181", nil)

	if k8sCollectorEnabled {
		<-k8sCollector.Done()
		log.Logger.Info().Msg("k8sCollector done")
	}

	if ebpfEnabled {
		<-ec.Done()
		log.Logger.Info().Msg("ebpfCollector done")
	}

	if logsEnabled {
		<-ct.Done()
		log.Logger.Info().Msg("cri done")
	}

	log.Logger.Info().Msg("alaz exiting...")
}
