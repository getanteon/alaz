package gpu

import (
	"fmt"
	"log"
	"sync"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

func decode(msg string, code nvml.Return) error {
	return fmt.Errorf("%s: %s", msg, nvml.ErrorString(code))
}

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
				opt = nvml.WithLibraryPath(soPath)
			}
			if !n.init(opt) {
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
		return nil, nil, decode("failed to get device info", code)
	}

	temp, code := nvml.DeviceGetTemperature(device, nvml.TEMPERATURE_GPU)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device temperature", code)
	}
	tempU := uint(temp)

	utz, code := nvml.DeviceGetUtilizationRates(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device utilization", code)
	}
	utzGPU := uint(utz.Gpu)
	utzMem := uint(utz.Memory)

	utzEnc, _, code := nvml.DeviceGetEncoderUtilization(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device encoder utilization", code)
	}
	utzEncU := uint(utzEnc)

	utzDec, _, code := nvml.Device.GetDecoderUtilization(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device decoder utilization", code)
	}
	utzDecU := uint(utzDec)

	mem, code := nvml.DeviceGetMemoryInfo(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device memory utilization", code)
	}

	memUsedU := mem.Used / (1 << 20)
	memTotalU := mem.Total / (1 << 20)
	memFreeU := mem.Free / (1 << 20)

	power, code := nvml.DeviceGetPowerUsage(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device power usage", code)
	}
	powerU := uint(power)

	bar, code := nvml.DeviceGetBAR1MemoryInfo(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device bar1 memory info", code)
	}
	barUsed := bar.Bar1Used / (1 << 20)

	//TODO: add GetEnforcedPowerLimit to devicestatus
	pwLimit, code := nvml.DeviceGetEnforcedPowerLimit(device)
	if code != nvml.SUCCESS {
		return nil, nil, decode("failed to get device power limit", code)
	}
	pwLimitU := uint(pwLimit)

	// note: ecc memory error stats removed; couldn't figure out the API
	return di, &DeviceStatus{
		TemperatureC:       &tempU,
		GPUUtilization:     &utzGPU,
		MemoryUtilization:  &utzMem,
		EncoderUtilization: &utzEncU,
		DecoderUtilization: &utzDecU,
		UsedMemoryMiB:      &memUsedU,
		TotalMemoryMiB:     &memTotalU,
		FreeMemoryMiB:      &memFreeU,
		PowerUsageW:        &powerU,
		BAR1UsedMiB:        &barUsed,
		PowerLimit:         &pwLimitU,
	}, nil
}

func buildID(id [32]int8) string {
	b := make([]byte, len(id), len(id))
	for i := 0; i < len(id); i++ {
		b[i] = byte(id[i])
	}
	return string(b)
}

// DeviceInfoByIndex returns DeviceInfo for index GPU in system device list.
func (n *nvmlDriver) DeviceInfoByIndex(index uint) (*DeviceInfo, error) {
	device, code := nvml.DeviceGetHandleByIndex(int(index))
	// TODO: if only one fails, remainder should be retrieved

	if code != nvml.SUCCESS {
		return nil, decode("failed to get device info", code)
	}

	uuid, code := nvml.DeviceGetUUID(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device uuid", code)
	}

	name, code := nvml.Device.GetName(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device name", code)
	}

	memory, code := nvml.DeviceGetMemoryInfo(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device memory info", code)
	}
	memoryTotal := memory.Total / (1 << 20)

	power, code := nvml.DeviceGetPowerUsage(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device power info", code)
	}
	powerU := uint(power) / 1000

	bar1, code := nvml.DeviceGetBAR1MemoryInfo(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device bar 1 memory info", code)
	}
	bar1total := bar1.Bar1Total / (1 << 20)

	pci, code := nvml.Device.GetPciInfo(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device pci info", code)
	}

	linkWidth, code := nvml.DeviceGetMaxPcieLinkWidth(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get pcie link width", code)
	}

	linkGeneration, code := nvml.DeviceGetMaxPcieLinkGeneration(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get pcie link generation", code)
	}

	// https://en.wikipedia.org/wiki/PCI_Express
	var bandwidth uint
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

	busID := buildID(pci.BusId)

	coreClock, code := nvml.DeviceGetClockInfo(device, nvml.CLOCK_GRAPHICS)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device core clock", code)
	}
	coreClockU := uint(coreClock)

	memClock, code := nvml.DeviceGetClockInfo(device, nvml.CLOCK_MEM)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device mem clock", code)
	}
	memClockU := uint(memClock)

	mode, code := nvml.DeviceGetDisplayMode(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device display mode", code)
	}

	persistence, code := nvml.DeviceGetPersistenceMode(device)
	if code != nvml.SUCCESS {
		return nil, decode("failed to get device persistence mode", code)
	}

	return &DeviceInfo{
		UUID:               uuid,
		Name:               &name,
		MemoryMiB:          &memoryTotal,
		PowerW:             &powerU,
		BAR1MiB:            &bar1total,
		PCIBandwidthMBPerS: &bandwidth,
		PCIBusID:           busID,
		CoresClockMHz:      &coreClockU,
		MemoryClockMHz:     &memClockU,
		DisplayState:       fmt.Sprintf("%v", mode),
		PersistenceMode:    fmt.Sprintf("%v", persistence),
	}, nil
}

func (n *nvmlDriver) printAllDeviceData() {
	dv, err := n.SystemDriverVersion()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("driver version: ", dv)
	fmt.Println("---------------------------------------------------------------------------------")

	count, err := n.DeviceCount()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("device count: ", count)
	n.deviceCount = count
	fmt.Println("---------------------------------------------------------------------------------")

	// devices are indexed
	for i := uint(0); i < count; i++ {
		devInfo, devStatus, err := n.DeviceInfoAndStatusByIndex(i)
		if err != nil {
			log.Fatal(err)
		}
		// fmt.Println("deviceInfo: ", *devInfo.Name, *devInfo.MemoryMiB, *devInfo.PowerW, *devInfo.BAR1MiB, *devInfo.PCIBandwidthMBPerS, devInfo.PCIBusID, *devInfo.CoresClockMHz, *devInfo.MemoryClockMHz, devInfo.DisplayState, devInfo.PersistenceMode)
		fmt.Printf(" name: %s \n memory: %d MB \n power: %d W \n bar1: %d MB \n pci bandwidth: %d MB/s \n pci bus id: %s \n core clock: %d MHz \n memory clock: %d MHz \n display state: %s \n persistence mode: %s\n", *devInfo.Name, *devInfo.MemoryMiB, *devInfo.PowerW, *devInfo.BAR1MiB, *devInfo.PCIBandwidthMBPerS, devInfo.PCIBusID, *devInfo.CoresClockMHz, *devInfo.MemoryClockMHz, devInfo.DisplayState, devInfo.PersistenceMode)
		fmt.Printf(" temperature: %d C \n gpu utilization: %d %% \n memory utilization: %d %% \n encoder utilization: %d %% \n decoder utilization: %d %% \n used memory: %d MB \n power usage: %d W \n bar1 used: %d MB \n", *devStatus.TemperatureC, *devStatus.GPUUtilization, *devStatus.MemoryUtilization, *devStatus.EncoderUtilization, *devStatus.DecoderUtilization, *devStatus.UsedMemoryMiB, *devStatus.PowerUsageW, *devStatus.BAR1UsedMiB)
		fmt.Println("---------------------------------------------------------------------------------")
	}
}
