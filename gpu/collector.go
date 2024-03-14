package gpu

import (
	"fmt"

	"github.com/ddosify/alaz/log"

	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

type MetricDesc struct {
	desc  *prometheus.Desc
	type_ prometheus.ValueType
}

type GpuCollector struct {
	fieldDesc     map[string]MetricDesc
	gpuDriverDesc *prometheus.Desc

	descs map[string]*prometheus.Desc

	n  *nvmlDriver
	mu sync.Mutex
}

var nvidiaPaths = []string{"/proc/1/root/run/nvidia/driver/lib64/libnvidia-ml.so", "/proc/1/root/lib64/libnvidia-ml.so", "/proc/1/root/lib/libnvidia-ml.so"}

func NewGpuCollector() (*GpuCollector, error) {
	var nvmlDriver *nvmlDriver
	var err error
	for _, path := range nvidiaPaths {
		nvmlDriver, err = getNvmlDriver(path)
		if err != nil {
			continue
		}
		break
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load nvidia driver: %v", err)
	}

	uuidLabel := []string{"uuid"}
	gpuCollector := &GpuCollector{
		n:  nvmlDriver,
		mu: sync.Mutex{},
		fieldDesc: map[string]MetricDesc{
			"gpu_info": {
				desc: prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "gpu_info"), "gpu_info_desc", []string{"uuid", "gpu_name",
					"displayState", "persistenceMode"}, nil),
				type_: prometheus.GaugeValue,
			},
			"power": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "power"), "power_in_watts", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"bar1": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "bar1"), "bar1_in_mib", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"pci_bandwidth": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "pci_bandwidth"), "pci_bandwidth_mb_per_s", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"core_clock_mhz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "core_clock_mhz"), "core_clock_mhz", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"mem_clock_mhz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "mem_clock_mhz"), "mem_clock_mhz", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"total_mem": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "total_mem"), "total_mem_in_mib", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"temp_celcius": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "temp_celcius"), "temperature_in_celcius", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"gpu_utz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "gpu_utz"), "gpu_utilization_percent", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"mem_utz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "mem_utz"), "mem_utilization_percent", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"enc_utz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "enc_utz"), "encoder_utilization_percent", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"dec_utz": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "dec_utz"), "decoder_utilization_percent", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"used_mem": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "used_mem"), "used_memory_in_mib", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"free_mem": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "free_mem"), "free_memory_in_mib", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"power_usage": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "power_usage"), "power_usage_watts", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"power_limit": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "power_limit"), "power_limit_watts", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"bar1_used": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "bar1_used"), "bar1_used_in_mib", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
			"fan_count": {
				desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "fan_count"), "fan_count_desc", uuidLabel, nil),
				type_: prometheus.GaugeValue,
			},
		},
		gpuDriverDesc: prometheus.NewDesc(
			prometheus.BuildFQName("alaz_nvml", "", "gpu_driver"),
			"gpu_driver_desc",
			[]string{"driver_version", "gpu_count", "cuda_version"},
			nil),
	}

	return gpuCollector, nil
}

// Collect implements prometheus.Collector
func (g *GpuCollector) Collect(ch chan<- prometheus.Metric) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// do scraping here
	count, err := g.n.DeviceCount()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to get gpu count, skipping gpu metrics collection")
		return
	}

	dv, err := g.n.SystemDriverVersion()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to get driver version for nvidia management library")
	}

	cv, err := g.n.CudaVersion()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to get cuda version")
	}

	// send driver version and gpu count in labels
	driverMetric := prometheus.MustNewConstMetric(g.gpuDriverDesc, prometheus.GaugeValue, 0, dv, fmt.Sprintf("%d", count), fmt.Sprintf("%d", cv))
	ch <- driverMetric

	// devices are indexed
	for i := uint(0); i < count; i++ {
		devInfo, devStatus, err := g.n.DeviceInfoAndStatusByIndex(i)
		if err != nil {
			log.Logger.Error().Str("ctx", "gpu").Err(err).Msgf("failed to get device info and status, skipping gpu metrics collection for device index: %d", i)
			continue
		}

		if devInfo == nil {
			continue
			// we need uuid to uniquely identify the device
		}

		// device info
		deviceName := ""
		if devInfo.Name != nil {
			deviceName = *devInfo.Name
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device name is nil for device index %d", i)
		}

		infoMetric := prometheus.MustNewConstMetric(g.fieldDesc["gpu_info"].desc, g.fieldDesc["gpu_info"].type_, float64(i), devInfo.UUID,
			deviceName,
			devInfo.DisplayState, devInfo.PersistenceMode)
		ch <- infoMetric

		if devInfo.PowerW != nil {
			powerWF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.PowerW), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse power in watts")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["power"].desc, g.fieldDesc["power"].type_, powerWF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device power is nil for device index %d", i)
		}

		if devInfo.BAR1MiB != nil {
			bar1F, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.BAR1MiB), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse bar1 in mib")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["bar1"].desc, g.fieldDesc["bar1"].type_, bar1F, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device bar1 is nil for device index %d", i)
		}

		if devInfo.PCIBandwidthMBPerS != nil {
			pciBandwidthMBPerSF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.PCIBandwidthMBPerS), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse pci bandwidth in mb per s")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["pci_bandwidth"].desc, g.fieldDesc["pci_bandwidth"].type_, pciBandwidthMBPerSF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device pci bandwidth is nil for device index %d", i)
		}

		if devInfo.CoresClockMHz != nil {
			coreClockMhzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.CoresClockMHz), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse core clock mhz")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["core_clock_mhz"].desc, g.fieldDesc["core_clock_mhz"].type_, coreClockMhzF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device core clock mhz is nil for device index %d", i)
		}

		if devInfo.MemoryClockMHz != nil {
			memClockMhzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.MemoryClockMHz), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse memory clock mhz")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["mem_clock_mhz"].desc, g.fieldDesc["mem_clock_mhz"].type_, memClockMhzF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device memory clock mhz is nil for device index %d", i)
		}

		// device status
		if devStatus == nil {
			log.Logger.Error().Str("ctx", "gpu").Msgf("device status is nil for device index %d, skipping device status metrics", i)
			continue
		}

		if devStatus.TemperatureC != nil {
			tempF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.TemperatureC), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse temperature in celcius")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["temp_celcius"].desc, g.fieldDesc["temp_celcius"].type_, tempF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device temperature is nil for device index %d", i)
		}

		if devStatus.GPUUtilization != nil {
			gpuUtzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.GPUUtilization), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse gpu utilization")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["gpu_utz"].desc, g.fieldDesc["gpu_utz"].type_, gpuUtzF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device gpu utilization is nil for device index %d", i)
		}

		if devStatus.MemoryUtilization != nil {
			memUtzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.MemoryUtilization), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse memory utilization")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["mem_utz"].desc, g.fieldDesc["mem_utz"].type_, memUtzF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device memory utilization is nil for device index %d", i)
		}

		if devStatus.EncoderUtilization != nil {
			encF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.EncoderUtilization), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse encoder utilization")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["enc_utz"].desc, g.fieldDesc["enc_utz"].type_, encF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device encoder utilization is nil for device index %d", i)
		}

		if devStatus.DecoderUtilization != nil {
			decF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.DecoderUtilization), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse decoder utilization")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["dec_utz"].desc, g.fieldDesc["dec_utz"].type_, decF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device decoder utilization is nil for device index %d", i)
		}

		if devStatus.UsedMemoryMiB != nil {
			usedMemF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.UsedMemoryMiB), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse used memory in mib")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["used_mem"].desc, g.fieldDesc["used_mem"].type_, usedMemF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device used memory is nil for device index %d", i)
		}

		if devStatus.FreeMemoryMiB != nil {
			freeMemF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.FreeMemoryMiB), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse free memory in mib")
			} else {
				temp := prometheus.MustNewConstMetric(g.fieldDesc["free_mem"].desc, g.fieldDesc["free_mem"].type_, freeMemF, devInfo.UUID)
				ch <- temp
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device free memory is nil for device index %d", i)
		}

		if devStatus.TotalMemoryMiB != nil {
			memF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.TotalMemoryMiB), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse total memory in mib")
			} else {
				total_mem := prometheus.MustNewConstMetric(g.fieldDesc["total_mem"].desc, g.fieldDesc["total_mem"].type_, memF, devInfo.UUID)
				ch <- total_mem
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device total memory is nil for device index %d", i)
		}

		if devStatus.PowerUsageW != nil {
			powerUsageF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.PowerUsageW), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse power usage in watts")
			} else {
				total_mem := prometheus.MustNewConstMetric(g.fieldDesc["power_usage"].desc, g.fieldDesc["power_usage"].type_, powerUsageF, devInfo.UUID)
				ch <- total_mem
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device power usage is nil for device index %d", i)
		}

		if devStatus.PowerLimit != nil {
			powerLimitF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.PowerLimit), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse power limit in watts")
			} else {
				total_mem := prometheus.MustNewConstMetric(g.fieldDesc["power_limit"].desc, g.fieldDesc["power_limit"].type_, powerLimitF, devInfo.UUID)
				ch <- total_mem
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device power limit is nil for device index %d", i)
		}

		if devStatus.BAR1UsedMiB != nil {
			bar1UsedF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.BAR1UsedMiB), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse bar1 used in mib")
			} else {
				total_mem := prometheus.MustNewConstMetric(g.fieldDesc["bar1_used"].desc, g.fieldDesc["bar1_used"].type_, bar1UsedF, devInfo.UUID)
				ch <- total_mem
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device bar1 used is nil for device index %d", i)
		}

		if devStatus.FanCount != nil {
			fanCountF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.FanCount), 64)
			if err != nil {
				log.Logger.Error().Str("ctx", "gpu").Err(err).Msg("failed to parse fan count")
			} else {
				total_mem := prometheus.MustNewConstMetric(g.fieldDesc["fan_count"].desc, g.fieldDesc["fan_count"].type_, fanCountF, devInfo.UUID)
				ch <- total_mem
			}
		} else {
			log.Logger.Warn().Str("ctx", "gpu").Msgf("device fan count is nil for device index %d", i)
		}
	}
}

// Describe implements prometheus.Collector
func (g *GpuCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range g.fieldDesc {
		ch <- m.desc
	}
	ch <- g.gpuDriverDesc
}

func (g *GpuCollector) Close() {
	g.n.close()
}
