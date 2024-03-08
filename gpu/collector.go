package gpu

import (
	"fmt"
	"log"
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
			// "ecc_errors_l1_cache": {
			// 	desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "ecc_errors_l1_cache"), "ecc_errors_l1_cache_desc", uuidLabel, nil),
			// 	type_: prometheus.GaugeValue,
			// },
			// "ecc_errors_l2_cache": {
			// 	desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "ecc_errors_l2_cache"), "ecc_errors_l2_cache_desc", uuidLabel, nil),
			// 	type_: prometheus.GaugeValue,
			// },
			// "ecc_errors_device": {
			// 	desc:  prometheus.NewDesc(prometheus.BuildFQName("alaz_nvml", "", "ecc_errors_device"), "ecc_errors_device_desc", uuidLabel, nil),
			// 	type_: prometheus.GaugeValue,
			// },
		},
		gpuDriverDesc: prometheus.NewDesc(
			prometheus.BuildFQName("alaz_nvml", "", "gpu_driver"),
			"gpu_driver_desc",
			[]string{"driver_version", "gpu_count"},
			nil),
	}

	return gpuCollector, nil
}

// Collect implements prometheus.Collector
func (g *GpuCollector) Collect(ch chan<- prometheus.Metric) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// do scraping here
	dv, err := g.n.SystemDriverVersion()
	if err != nil {
		log.Fatal(err)
	}

	count, err := g.n.DeviceCount()
	if err != nil {
		log.Fatal(err)
	}

	driverMetric := prometheus.MustNewConstMetric(g.gpuDriverDesc, prometheus.GaugeValue, 0, dv, fmt.Sprintf("%d", count))
	ch <- driverMetric

	// devices are indexed
	for i := uint(0); i < count; i++ {
		devInfo, devStatus, err := g.n.DeviceInfoAndStatusByIndex(i)
		if err != nil {
			log.Fatal(err)
		}

		infoMetric := prometheus.MustNewConstMetric(g.fieldDesc["gpu_info"].desc, g.fieldDesc["gpu_info"].type_, float64(i), devInfo.UUID,
			*devInfo.Name,
			devInfo.DisplayState, devInfo.PersistenceMode)
		ch <- infoMetric

		powerWF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.PowerW), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["power"].desc, g.fieldDesc["power"].type_, powerWF, devInfo.UUID)
			ch <- temp
		}

		bar1F, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.BAR1MiB), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["bar1"].desc, g.fieldDesc["bar1"].type_, bar1F, devInfo.UUID)
			ch <- temp
		}

		pciBandwidthMBPerSF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.PCIBandwidthMBPerS), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["pci_bandwidth"].desc, g.fieldDesc["pci_bandwidth"].type_, pciBandwidthMBPerSF, devInfo.UUID)
			ch <- temp
		}

		coreClockMhzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.CoresClockMHz), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["core_clock_mhz"].desc, g.fieldDesc["core_clock_mhz"].type_, coreClockMhzF, devInfo.UUID)
			ch <- temp
		}

		memClockMhzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devInfo.MemoryClockMHz), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["mem_clock_mhz"].desc, g.fieldDesc["mem_clock_mhz"].type_, memClockMhzF, devInfo.UUID)
			ch <- temp
		}

		tempF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.TemperatureC), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["temp_celcius"].desc, g.fieldDesc["temp_celcius"].type_, tempF, devInfo.UUID)
			ch <- temp
		}

		gpuUtzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.GPUUtilization), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["gpu_utz"].desc, g.fieldDesc["gpu_utz"].type_, gpuUtzF, devInfo.UUID)
			ch <- temp
		}

		memUtzF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.MemoryUtilization), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["mem_utz"].desc, g.fieldDesc["mem_utz"].type_, memUtzF, devInfo.UUID)
			ch <- temp
		}

		encF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.EncoderUtilization), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["enc_utz"].desc, g.fieldDesc["enc_utz"].type_, encF, devInfo.UUID)
			ch <- temp
		}

		decF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.DecoderUtilization), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["dec_utz"].desc, g.fieldDesc["dec_utz"].type_, decF, devInfo.UUID)
			ch <- temp
		}

		fmt.Printf("  %% \n used memory: %d MB \n power usage: %d W \n bar1 used: %d MB \n",
			*devStatus.UsedMemoryMiB, *devStatus.PowerUsageW, *devStatus.BAR1UsedMiB)

		usedMemF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.UsedMemoryMiB), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["used_mem"].desc, g.fieldDesc["used_mem"].type_, usedMemF, devInfo.UUID)
			ch <- temp
		}

		freeMemF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.FreeMemoryMiB), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			temp := prometheus.MustNewConstMetric(g.fieldDesc["free_mem"].desc, g.fieldDesc["free_mem"].type_, freeMemF, devInfo.UUID)
			ch <- temp
		}

		memF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.TotalMemoryMiB), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			total_mem := prometheus.MustNewConstMetric(g.fieldDesc["total_mem"].desc, g.fieldDesc["total_mem"].type_, memF, devInfo.UUID)
			ch <- total_mem
		}

		powerUsageF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.PowerUsageW), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			total_mem := prometheus.MustNewConstMetric(g.fieldDesc["power_usage"].desc, g.fieldDesc["power_usage"].type_, powerUsageF, devInfo.UUID)
			ch <- total_mem
		}

		powerLimitF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.PowerLimit), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			total_mem := prometheus.MustNewConstMetric(g.fieldDesc["power_limit"].desc, g.fieldDesc["power_limit"].type_, powerLimitF, devInfo.UUID)
			ch <- total_mem
		}

		bar1UsedF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.BAR1UsedMiB), 64)
		if err != nil {
			log.Default().Println("error: ", err)
			continue
		} else {
			total_mem := prometheus.MustNewConstMetric(g.fieldDesc["bar1_used"].desc, g.fieldDesc["bar1_used"].type_, bar1UsedF, devInfo.UUID)
			ch <- total_mem
		}

		// eccErrorsL1CacheF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.ECCErrorsL1Cache), 64)
		// if err != nil {
		// 	log.Default().Println("error: ", err)
		// 	continue
		// } else {
		// 	total_mem := prometheus.MustNewConstMetric(g.fieldDesc["ecc_errors_l1_cache"].desc, g.fieldDesc["ecc_errors_l1_cache"].type_, eccErrorsL1CacheF, devInfo.UUID)
		// 	ch <- total_mem
		// }

		// eccErrorsL2CacheF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.ECCErrorsL2Cache), 64)
		// if err != nil {
		// 	log.Default().Println("error: ", err)
		// 	continue
		// } else {
		// 	total_mem := prometheus.MustNewConstMetric(g.fieldDesc["ecc_errors_l2_cache"].desc, g.fieldDesc["ecc_errors_l2_cache"].type_, eccErrorsL2CacheF, devInfo.UUID)
		// 	ch <- total_mem
		// }

		// eccErrorsDeviceF, err := strconv.ParseFloat(fmt.Sprintf("%d", *devStatus.ECCErrorsDevice), 64)
		// if err != nil {
		// 	log.Default().Println("error: ", err)
		// 	continue
		// } else {
		// 	total_mem := prometheus.MustNewConstMetric(g.fieldDesc["ecc_errors_device"].desc, g.fieldDesc["ecc_errors_device"].type_, eccErrorsDeviceF, devInfo.UUID)
		// 	ch <- total_mem
		// }
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
