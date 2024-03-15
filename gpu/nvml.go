package gpu

import (
	"fmt"
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/ddosify/alaz/log"
)

var lock = &sync.Mutex{}

// nvml stands for Nvidia Management Library
type nvmlDriver struct {
	initResult  nvml.Return
	deviceCount uint
}

var singleInstance *nvmlDriver

func getNvmlDriver(soPath string) (*nvmlDriver, error) {
	if singleInstance == nil {
		lock.Lock()
		defer lock.Unlock()
		if singleInstance == nil {
			n := &nvmlDriver{}
			var opt nvml.LibraryOption
			if soPath != "" {
				log.Logger.Info().Str("soPath", soPath).Msg("getNvmlDriver")
				opt = nvml.WithLibraryPath(soPath)
			}
			initSuccess := n.init(opt)
			log.Logger.Info().Bool("initSuccess", initSuccess).Msg("getNvmlDriver")
			if !initSuccess {
				return nil, fmt.Errorf("failed to initialize nvml")
			}
			singleInstance = n
		}
	}

	return singleInstance, nil
}

func (n *nvmlDriver) init(opts ...nvml.LibraryOption) bool {
	defer func() {
		if r := recover(); r != nil {
			n.initResult = nvml.ERROR_UNINITIALIZED
		}
	}()
	nvml.SetLibraryOptions(opts...)
	n.initResult = nvml.Init()
	return n.initResult == nvml.SUCCESS
}

func (n *nvmlDriver) close() {
	nvml.Shutdown()
}

// SystemDriverVersion returns installed driver version
func (n *nvmlDriver) SystemDriverVersion() (string, error) {
	version, code := nvml.SystemGetDriverVersion()
	if code != nvml.SUCCESS {
		return "", fmt.Errorf("nvml.SystemGetDriverVersion: %v", nvml.ErrorString(code))
	}
	return version, nil
}

func (n *nvmlDriver) DeviceCount() (uint, error) {
	count, code := nvml.DeviceGetCount()
	if code != nvml.SUCCESS {
		return 0, fmt.Errorf("nvml.DeviceGetCount: %v", nvml.ErrorString(code))
	}
	return uint(count), nil
}

func (n *nvmlDriver) CudaVersion() (uint, error) {
	cudaVersion, code1 := nvml.SystemGetCudaDriverVersion_v2()
	if code1 != nvml.SUCCESS {
		var code2 nvml.Return
		cudaVersion, code2 = nvml.SystemGetCudaDriverVersion()
		if code2 != nvml.SUCCESS {
			return 0, fmt.Errorf("nvml.SystemGetCudaDriverVersion: %v,%v", nvml.ErrorString(code1), nvml.ErrorString(code2))
		}
	}
	return uint(cudaVersion), nil
}

// DeviceInfo represents nvml device data
// this struct is returned by NvmlDriver DeviceInfoByIndex and
// DeviceInfoAndStatusByIndex methods
type DeviceInfo struct {
	// The following fields are guaranteed to be retrieved from nvml
	UUID            string
	PCIBusID        string
	DisplayState    string
	PersistenceMode string

	// The following fields can be nil after call to nvml, because nvml was
	// not able to retrieve this fields for specific nvidia card
	Name               *string
	MemoryMiB          *uint64
	PowerW             *uint
	BAR1MiB            *uint64
	PCIBandwidthMBPerS *uint
	CoresClockMHz      *uint
	MemoryClockMHz     *uint
}

// DeviceStatus represents nvml device status
// this struct is returned by NvmlDriver DeviceInfoAndStatusByIndex method
type DeviceStatus struct {
	// The following fields can be nil after call to nvml, because nvml was
	// not able to retrieve this fields for specific nvidia card
	PowerUsageW        *uint
	TemperatureC       *uint
	GPUUtilization     *uint // %
	MemoryUtilization  *uint // %
	EncoderUtilization *uint // %
	DecoderUtilization *uint // %
	PowerLimit         *uint
	FanCount           *uint
	FanSpeeds          map[int]uint // index = fanID, value = speed
	BAR1UsedMiB        *uint64
	UsedMemoryMiB      *uint64
	TotalMemoryMiB     *uint64
	FreeMemoryMiB      *uint64
	ECCErrorsL1Cache   *uint64
	ECCErrorsL2Cache   *uint64
	ECCErrorsDevice    *uint64
}

// DeviceInfoAndStatusByIndex returns DeviceInfo and DeviceStatus for index GPU in system device list.
func (n *nvmlDriver) DeviceInfoAndStatusByIndex(index uint) (*DeviceInfo, *DeviceStatus, error) {
	di, err := n.DeviceInfoByIndex(index)
	if err != nil {
		return nil, nil, err
	}

	device, code := nvml.DeviceGetHandleByIndex(int(index))
	if code != nvml.SUCCESS {
		return nil, nil, fmt.Errorf("failed to get device %s", nvml.ErrorString(code))
	}

	var tempU *uint
	temp, code := nvml.DeviceGetTemperature(device, nvml.TEMPERATURE_GPU)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetTemperature").Msgf("failed to get device temperature : %s", nvml.ErrorString(code))
	} else {
		t := uint(temp)
		tempU = &t
	}

	var utzGPU, utzMem *uint
	utz, code := nvml.DeviceGetUtilizationRates(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetUtilizationRates").Msgf("failed to get device utilization rates : %s", nvml.ErrorString(code))
	} else {
		t := uint(utz.Gpu)
		utzGPU = &t
		tt := uint(utz.Memory)
		utzMem = &tt
	}

	var utzEncU, utzDecU *uint
	utzEnc, _, code := nvml.DeviceGetEncoderUtilization(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetEncoderUtilization").Msgf("failed to get device encoder utilization : %s", nvml.ErrorString(code))
	} else {
		t := uint(utzEnc)
		utzEncU = &t
	}

	utzDec, _, code := nvml.Device.GetDecoderUtilization(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.GetDecoderUtilization").Msgf("failed to get device decoder utilization : %s", nvml.ErrorString(code))
	} else {
		t := uint(utzDec)
		utzDecU = &t
	}

	var memUsedU, memTotalU, memFreeU *uint64
	mem, code := nvml.DeviceGetMemoryInfo(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetMemoryInfo").Msgf("failed to get device memory utilization : %s", nvml.ErrorString(code))
	} else {
		t := mem.Used / (1 << 20)
		memUsedU = &t

		tt := mem.Total / (1 << 20)
		memTotalU = &tt

		ttt := mem.Free / (1 << 20)
		memFreeU = &ttt
	}

	var powerU *uint
	power, code := nvml.DeviceGetPowerUsage(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetPowerUsage").Msgf("failed to get device power usage : %s", nvml.ErrorString(code))
	} else {
		t := uint(power)
		powerU = &t
	}

	var barUsed *uint64
	bar, code := nvml.DeviceGetBAR1MemoryInfo(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetBAR1MemoryInfo").Msgf("failed to get device bar1 memory info : %s", nvml.ErrorString(code))
	} else {
		t := bar.Bar1Used / (1 << 20)
		barUsed = &t
	}

	var pwLimitU *uint
	pwLimit, code := nvml.DeviceGetEnforcedPowerLimit(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetEnforcedPowerLimit").Msgf("failed to get device power limit : %s", nvml.ErrorString(code))
	} else {
		t := uint(pwLimit)
		pwLimitU = &t
	}

	var fanCountU *uint
	fanCount, code := nvml.DeviceGetNumFans(device)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetNumFans").Msgf("failed to get fan count : %s", nvml.ErrorString(code))
	} else {
		t := uint(fanCount)
		fanCountU = &t
	}

	fanSpeeds := make(map[int]uint, 0)
	for i := 0; i < int(fanCount); i++ {
		speed, err := n.GetFanSpeed(device, i)
		if err != nil {
			log.Logger.Error().Str("ctx", "gpu").Msgf("failed to get fan speed : %s", err)
			continue
		}
		fanSpeeds[i] = speed
	}

	// note: ecc memory error stats removed; couldn't figure out the API
	return di, &DeviceStatus{
		TemperatureC:       tempU,
		GPUUtilization:     utzGPU,
		MemoryUtilization:  utzMem,
		EncoderUtilization: utzEncU,
		DecoderUtilization: utzDecU,
		UsedMemoryMiB:      memUsedU,
		TotalMemoryMiB:     memTotalU,
		FreeMemoryMiB:      memFreeU,
		PowerUsageW:        powerU,
		BAR1UsedMiB:        barUsed,
		PowerLimit:         pwLimitU,
		FanCount:           fanCountU,
		FanSpeeds:          fanSpeeds,
	}, nil
}

func buildID(id [32]int8) string {
	b := make([]byte, len(id), len(id))
	for i := 0; i < len(id); i++ {
		b[i] = byte(id[i])
	}
	return string(b)
}

func (n *nvmlDriver) GetFanSpeed(device nvml.Device, fanID int) (uint, error) {
	fanSpeed, code := nvml.DeviceGetFanSpeed_v2(device, fanID)
	if code != nvml.SUCCESS {
		log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetFanSpeed_v2").Msgf("failed to get fan speed : %s", nvml.ErrorString(code))
		fanSpeed, code = nvml.DeviceGetFanSpeed(device)
		if code != nvml.SUCCESS {
			log.Logger.Error().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetFanSpeed").Msgf("failed to get fan speed : %s", nvml.ErrorString(code))
		} else {
			return uint(fanSpeed), nil
		}
		return 0, fmt.Errorf("failed to get fan speed: %s", nvml.ErrorString(code))
	}
	return uint(fanSpeed), nil
}

// DeviceInfoByIndex returns DeviceInfo for index GPU in system device list.
func (n *nvmlDriver) DeviceInfoByIndex(index uint) (*DeviceInfo, error) {
	device, code := nvml.DeviceGetHandleByIndex(int(index))

	if code != nvml.SUCCESS {
		return nil, fmt.Errorf("failed to get device handle: %s", nvml.ErrorString(code))
	}

	uuid, code := nvml.DeviceGetUUID(device)
	if code != nvml.SUCCESS {
		return nil, fmt.Errorf("failed to get device uuid with nvml.DeviceGetUUID: %s", nvml.ErrorString(code))
	}

	var namep *string
	name, code := nvml.Device.GetName(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetName").Msgf("failed to get device name : %s", nvml.ErrorString(code))
	} else {
		namep = &name
	}

	var memoryTotal *uint64
	memory, code := nvml.DeviceGetMemoryInfo(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetMemoryInfo").Msgf("failed to get device mem info : %s", nvml.ErrorString(code))
	} else {
		t := memory.Total / (1 << 20)
		memoryTotal = &t
	}

	var powerU *uint
	power, code := nvml.DeviceGetPowerUsage(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetPowerUsage").Msgf("failed to get device power info : %s", nvml.ErrorString(code))
	} else {
		t := uint(power) / 1000
		powerU = &t
	}

	var bar1total *uint64
	bar1, code := nvml.DeviceGetBAR1MemoryInfo(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetPowerUsage").Msgf("failed to get device bar 1 memory info : %s", nvml.ErrorString(code))
	} else {
		t := bar1.Bar1Total / (1 << 20)
		bar1total = &t
	}

	var coreClockU, memClockU *uint
	coreClock, code := nvml.DeviceGetClockInfo(device, nvml.CLOCK_GRAPHICS)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetClockInfo").Msgf("failed to get core clock : %s", nvml.ErrorString(code))
	} else {
		t := uint(coreClock)
		coreClockU = &t
	}

	memClock, code := nvml.DeviceGetClockInfo(device, nvml.CLOCK_MEM)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetClockInfo").Msgf("failed to get mem clock : %s", nvml.ErrorString(code))
	} else {
		t := uint(memClock)
		memClockU = &t
	}

	mode, code := nvml.DeviceGetDisplayMode(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetDisplayMode").Msgf("failed to get display mode : %s", nvml.ErrorString(code))
	}

	persistence, code := nvml.DeviceGetPersistenceMode(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetDisplayMode").Msgf("failed to get persistence mode : %s", nvml.ErrorString(code))
	}

	var busID string
	pci, code := nvml.Device.GetPciInfo(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.GetPciInfo").Msgf("failed to get pci info and busID : %s", nvml.ErrorString(code))
	} else {
		busID = buildID(pci.BusId)
	}

	var width, gen bool
	linkWidth, code := nvml.DeviceGetMaxPcieLinkWidth(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetMaxPcieLinkWidth").Msgf("failed to get max pcie link width : %s", nvml.ErrorString(code))
	} else {
		width = true
	}
	linkGeneration, code := nvml.DeviceGetMaxPcieLinkGeneration(device)
	if code != nvml.SUCCESS {
		log.Logger.Warn().Str("ctx", "gpu").Str("binding", "nvml.DeviceGetMaxPcieLinkGeneration").Msgf("failed to get max pcie link generation : %s", nvml.ErrorString(code))
	} else {
		gen = true
	}

	var bandwidth uint
	var bandwidthp *uint

	if width && gen {
		// https://en.wikipedia.org/wiki/PCI_Express
		switch linkGeneration {
		case 6:
			bandwidth = uint(linkWidth) * (4 << 10)
		case 5:
			bandwidth = uint(linkWidth) * (3 << 10)
		case 4:
			bandwidth = uint(linkWidth) * (2 << 10)
		case 3:
			bandwidth = uint(linkWidth) * (1 << 10)
		}
		bandwidthp = &bandwidth
	}

	return &DeviceInfo{
		UUID:               uuid,
		Name:               namep,
		MemoryMiB:          memoryTotal,
		PowerW:             powerU,
		BAR1MiB:            bar1total,
		CoresClockMHz:      coreClockU,
		MemoryClockMHz:     memClockU,
		DisplayState:       fmt.Sprintf("%v", mode),
		PersistenceMode:    fmt.Sprintf("%v", persistence),
		PCIBusID:           busID,
		PCIBandwidthMBPerS: bandwidthp,
	}, nil
}

func (n *nvmlDriver) printAllDeviceData() {
	dv, err := n.SystemDriverVersion()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to get driver version")
	}
	fmt.Println("driver version: ", dv)
	fmt.Println("---------------------------------------------------------------------------------")

	count, err := n.DeviceCount()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to get device count")
	}
	fmt.Println("device count: ", count)
	n.deviceCount = count
	fmt.Println("---------------------------------------------------------------------------------")

	// devices are indexed
	for i := uint(0); i < count; i++ {
		devInfo, devStatus, err := n.DeviceInfoAndStatusByIndex(i)
		if err != nil {
			log.Logger.Fatal().Err(err).Msg("failed to get device info")
		}
		// fmt.Println("deviceInfo: ", *devInfo.Name, *devInfo.MemoryMiB, *devInfo.PowerW, *devInfo.BAR1MiB, *devInfo.PCIBandwidthMBPerS, devInfo.PCIBusID, *devInfo.CoresClockMHz, *devInfo.MemoryClockMHz, devInfo.DisplayState, devInfo.PersistenceMode)
		fmt.Printf(" name: %s \n memory: %d MB \n power: %d W \n bar1: %d MB \n pci bandwidth: %d MB/s \n pci bus id: %s \n core clock: %d MHz \n memory clock: %d MHz \n display state: %s \n persistence mode: %s\n", *devInfo.Name, *devInfo.MemoryMiB, *devInfo.PowerW, *devInfo.BAR1MiB, *devInfo.PCIBandwidthMBPerS, devInfo.PCIBusID, *devInfo.CoresClockMHz, *devInfo.MemoryClockMHz, devInfo.DisplayState, devInfo.PersistenceMode)
		fmt.Printf(" temperature: %d C \n gpu utilization: %d %% \n memory utilization: %d %% \n encoder utilization: %d %% \n decoder utilization: %d %% \n used memory: %d MB \n power usage: %d W \n bar1 used: %d MB \n", *devStatus.TemperatureC, *devStatus.GPUUtilization, *devStatus.MemoryUtilization, *devStatus.EncoderUtilization, *devStatus.DecoderUtilization, *devStatus.UsedMemoryMiB, *devStatus.PowerUsageW, *devStatus.BAR1UsedMiB)
		fmt.Println("---------------------------------------------------------------------------------")
	}
}
