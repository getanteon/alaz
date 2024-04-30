package main

import (
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"

	"github.com/ddosify/alaz/aggregator"
	"github.com/ddosify/alaz/config"
	"github.com/ddosify/alaz/cri"
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/k8s"
	"github.com/ddosify/alaz/logstreamer"

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

	var nsFilterRx *regexp.Regexp
	if os.Getenv("EXCLUDE_NAMESPACES") != "" {
		nsFilterRx = regexp.MustCompile(os.Getenv("EXCLUDE_NAMESPACES"))
	}

	stopAndWait := false
	var nsFilterStr string
	if nsFilterRx != nil {
		nsFilterStr = nsFilterRx.String()
	}

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

	tracingEnabled, err := strconv.ParseBool(os.Getenv("TRACING_ENABLED"))
	if err != nil {
		// for backwards compatibility
		ebpfEnabled, _ := strconv.ParseBool(os.Getenv("SERVICE_MAP_ENABLED"))
		distTracingEnabled, _ := strconv.ParseBool(os.Getenv("DIST_TRACING_ENABLED"))
		tracingEnabled = ebpfEnabled || distTracingEnabled
	}

	metricsEnabled, _ := strconv.ParseBool(os.Getenv("METRICS_ENABLED"))
	logsEnabled, _ := strconv.ParseBool(os.Getenv("LOGS_ENABLED"))

	// datastore backend
	dsBackend := datastore.NewBackendDS(ctx, config.BackendDSConfig{
		Host:                  os.Getenv("BACKEND_HOST"),
		MetricsExport:         metricsEnabled,
		GpuMetricsExport:      metricsEnabled,
		MetricsExportInterval: 10,
		ReqBufferSize:         40000, // TODO: get from a conf file
		ConnBufferSize:        1000,  // TODO: get from a conf file
	})

	var ct *cri.CRITool
	ct, err = cri.NewCRITool(ctx)
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to create cri tool")
	}

	// deploy ebpf programs
	var ec *ebpf.EbpfCollector
	if tracingEnabled {
		ec = ebpf.NewEbpfCollector(ctx, ct)

		a := aggregator.NewAggregator(ctx, kubeEvents, ec.EbpfEvents(), ec.EbpfProcEvents(), ec.EbpfTcpEvents(), ec.TlsAttachQueue(), dsBackend)
		a.Run()

		ec.Init()
		go ec.ListenEvents()
	}

	var ls *logstreamer.LogStreamer
	if logsEnabled {
		if ct != nil {
			go func() {
				backoff := 5 * time.Second
				for {
					// retry creating LogStreamer with backoff
					// it will throw an error if connection to backend is not established
					log.Logger.Info().Msg("creating logstreamer")
					ls, err = logstreamer.NewLogStreamer(ctx, ct)
					if err != nil {
						log.Logger.Error().Err(err).Msg("failed to create logstreamer")
						select {
						case <-time.After(backoff):
						case <-ctx.Done():
							return
						}
						backoff *= 2
					} else {
						break
					}
				}

				err := ls.StreamLogs()
				if err != nil {
					log.Logger.Error().Err(err).Msg("failed to stream logs")
				}
			}()

		} else {
			log.Logger.Error().Msg("logs enabled but cri tool not available")
		}
	}

	dsBackend.Start()

	healthCh := dsBackend.SendHealthCheck(tracingEnabled, metricsEnabled, logsEnabled, nsFilterStr, k8sVersion)
	go func() {
		for msg := range healthCh {
			if msg == datastore.HealthCheckActionStop {
				stopAndWait = true
				cancel()
				break
			}
		}
	}()

	go http.ListenAndServe(":8181", nil)

	if k8sCollectorEnabled {
		<-k8sCollector.Done()
		log.Logger.Info().Msg("k8sCollector done")
	}

	if tracingEnabled {
		<-ec.Done()
		log.Logger.Info().Msg("ebpfCollector done")
	}

	if logsEnabled && ls != nil {
		<-ls.Done()
		log.Logger.Info().Msg("cri done")
	}

	if stopAndWait {
		log.Logger.Warn().Msg("Payment required. Alaz will restart itself after payment's been made.")
		for msg := range healthCh {
			if msg == datastore.HealthCheckActionOK {
				log.Logger.Info().Msg("Restarting alaz...")
				break
			}
		}
	} else {
		log.Logger.Info().Msg("alaz exiting...")
	}
}
