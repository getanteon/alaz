package tcp_state

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"unsafe"

	"github.com/ddosify/alaz/log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/ebpf/linux"
)

// match with values in tcp_state.c
const (
	BPF_EVENT_TCP_ESTABLISHED = iota + 1
	BPF_EVENT_TCP_CONNECT_FAILED
	BPF_EVENT_TCP_LISTEN
	BPF_EVENT_TCP_LISTEN_CLOSED
	BPF_EVENT_TCP_CLOSED
)

// for user space
const (
	EVENT_TCP_ESTABLISHED    = "EVENT_TCP_ESTABLISHED"
	EVENT_TCP_CONNECT_FAILED = "EVENT_TCP_CONNECT_FAILED"
	EVENT_TCP_LISTEN         = "EVENT_TCP_LISTEN"
	EVENT_TCP_LISTEN_CLOSED  = "EVENT_TCP_LISTEN_CLOSED"
	EVENT_TCP_CLOSED         = "EVENT_TCP_CLOSED"
)

// Custom type for the enumeration
type TcpStateConversion uint32

// String representation of the enumeration values
func (e TcpStateConversion) String() string {
	switch e {
	case BPF_EVENT_TCP_ESTABLISHED:
		return EVENT_TCP_ESTABLISHED
	case BPF_EVENT_TCP_CONNECT_FAILED:
		return EVENT_TCP_CONNECT_FAILED
	case BPF_EVENT_TCP_LISTEN:
		return EVENT_TCP_LISTEN
	case BPF_EVENT_TCP_LISTEN_CLOSED:
		return EVENT_TCP_LISTEN_CLOSED
	case BPF_EVENT_TCP_CLOSED:
		return EVENT_TCP_CLOSED
	default:
		return "Unknown"
	}
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcp_sockets.c -- -I../headers

const mapKey uint32 = 0

// padding to match the kernel struct
type BpfTcpEvent struct {
	Fd        uint64
	Timestamp uint64
	Type      uint32
	Pid       uint32
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte
}

// for user space
type TcpConnectEvent struct {
	Fd        uint64
	Timestamp uint64
	Type_     string
	Pid       uint32
	SPort     uint16
	DPort     uint16
	SAddr     string
	DAddr     string
}

const TCP_CONNECT_EVENT = "tcp_connect_event"

func (e TcpConnectEvent) Type() string {
	return TCP_CONNECT_EVENT
}

var objs bpfObjects

var TcpState *TcpStateProg

type TcpStateConfig struct {
	BpfMapSize uint32 // specified in terms of os page size
}

var defaultConfig *TcpStateConfig = &TcpStateConfig{
	BpfMapSize: 64,
}

func InitTcpStateProg(conf *TcpStateConfig) *TcpStateProg {
	if conf == nil {
		conf = defaultConfig
	}

	return &TcpStateProg{
		links:             map[string]link.Link{},
		tcpConnectMapSize: conf.BpfMapSize,
	}
}

type TcpStateProg struct {
	// links represent a program attached to a hook
	links map[string]link.Link // key : hook name

	tcpConnectMapSize uint32
	tcpConnectEvents  *perf.Reader
	logs              *perf.Reader

	ContainerPidMap *ebpf.Map // for filtering non-container pids on the node
}

func (tsp *TcpStateProg) Close() {
	for hookName, link := range tsp.links {
		log.Logger.Info().Msgf("unattach %s", hookName)
		link.Close()
	}
	objs.Close()
}

// Loads bpf programs into kernel
func (tsp *TcpStateProg) Load() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs = bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}

	linux.FlushCaches()
}

func (tsp *TcpStateProg) Attach() {
	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.bpfPrograms.InetSockSetState, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link inet_sock_set_state tracepoint")
	}
	tsp.links["sock/inet_sock_set_state"] = l

	l1, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_connect tracepoint")
	}
	tsp.links["syscalls/sys_enter_connect"] = l1

	l2, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_connect tracepoint")
	}
	tsp.links["syscalls/sys_exit_connect"] = l2
}

func (tsp *TcpStateProg) InitMaps() {
	var err error
	tsp.tcpConnectEvents, err = perf.NewReader(objs.TcpConnectEvents, int(tsp.tcpConnectMapSize)*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	tsp.logs, err = perf.NewReader(objs.LogMap, 4*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	tsp.ContainerPidMap = objs.ContainerPids
}

func (tsp *TcpStateProg) PopulateContainerPidsMap(newKeys, deletedKeys []uint32) error {
	errors := []error{}
	if len(deletedKeys) > 0 {
		log.Logger.Debug().Msgf("deleting container pids map with %d new keys %v", len(deletedKeys), deletedKeys)
		count, err := tsp.ContainerPidMap.BatchDelete(deletedKeys, &ebpf.BatchOptions{})
		if err != nil {
			log.Logger.Warn().Err(err).Msg("failed deleting entries from container pids map")
			errors = append(errors, err)
		} else {
			log.Logger.Debug().Msgf("deleted %d entries from container pids map", count)
		}
	}

	if len(newKeys) > 0 {
		log.Logger.Debug().Msgf("adding container pids map with %d new keys %v", len(newKeys), newKeys)
		values := make([]uint8, len(newKeys))
		for i := range values {
			values[i] = 1
		}

		count, err := tsp.ContainerPidMap.BatchUpdate(newKeys, values, &ebpf.BatchOptions{
			ElemFlags: 0,
			Flags:     0,
		})

		if err != nil {
			errors = append(errors, fmt.Errorf("failed adding ebpfcontainer pids map, %v", err))
		} else {
			log.Logger.Debug().Msgf("updated %d entries in container pids map", count)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors: %v", errors)
	}

	return nil
}

func findEndIndex(b [100]uint8) (endIndex int) {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return len(b)
}

// returns when program is detached
func (tsp *TcpStateProg) Consume(ctx context.Context, ch chan interface{}) {
	stop := make(chan struct{})

	go func() {
		var logMessage []byte
		var funcName []byte
		read := func() {
			record, err := tsp.logs.Read()
			log.Logger.Debug().Msg("reading from log perf array")
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost #%d bpf logs", record.LostSamples)
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Warn().Msgf("read empty record from log perf array")
				return
			}

			logMsg := (*bpfLogMessage)(unsafe.Pointer(&record.RawSample[0]))

			funcEnd := findEndIndex(logMsg.FuncName)
			msgEnd := findEndIndex(logMsg.LogMsg)

			logMessage = logMsg.LogMsg[:msgEnd]
			funcName = logMsg.FuncName[:funcEnd]

			args := []struct {
				argName  string
				argValue uint64
			}{
				{
					argName:  "",
					argValue: 0,
				},
				{
					argName:  "",
					argValue: 0,
				},
				{
					argName:  "",
					argValue: 0,
				},
			}

			parseLogMessage := func(input []byte, logMsg *bpfLogMessage) []byte {
				// fd,x,y -- {log-msg}
				// fd,, -- {log-msg}

				parts := bytes.SplitN(input, []byte(" -- "), 2)
				if len(parts) != 2 {
					log.Logger.Warn().Msgf("invalid ebpf log message: %s", string(input))
					return nil
				}

				parsedArgs := bytes.SplitN(parts[1], []byte("|"), 3)
				if len(parsedArgs) != 3 {
					log.Logger.Warn().Msgf("invalid ebpf log message not 3 args: %s", string(input))
					return nil
				}

				args[0].argName = string(parsedArgs[0])
				args[0].argValue = logMsg.Arg1

				args[1].argName = string(parsedArgs[1])
				args[1].argValue = logMsg.Arg2

				args[2].argName = string(parsedArgs[2])
				args[2].argValue = logMsg.Arg3
				return parts[0]
			}

			// will change resultArgs
			logMessage = parseLogMessage(logMessage, logMsg)
			if logMessage == nil {
				log.Logger.Warn().Msgf("invalid ebpf log message: %s", string(logMsg.LogMsg[:]))
				return
			}

			switch logMsg.Level {
			case 0:
				log.Logger.Debug().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 1:
				log.Logger.Info().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 2:
				log.Logger.Warn().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 3:
				log.Logger.Error().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			}
		}
		for {
			select {
			case <-stop:
				return
			default:
				read()
			}
		}
	}()

	for {
		read := func() {
			record, err := tsp.tcpConnectEvents.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from tcp connect event map")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost samples tcp-connect %d", record.LostSamples)
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				return
			}

			bpfEvent := (*BpfTcpEvent)(unsafe.Pointer(&record.RawSample[0]))

			go func() {
				ch <- &TcpConnectEvent{
					Pid:       bpfEvent.Pid,
					Fd:        bpfEvent.Fd,
					Timestamp: bpfEvent.Timestamp,
					Type_:     TcpStateConversion(bpfEvent.Type).String(),
					SPort:     bpfEvent.SPort,
					DPort:     bpfEvent.DPort,
					SAddr:     fmt.Sprintf("%d.%d.%d.%d", bpfEvent.SAddr[0], bpfEvent.SAddr[1], bpfEvent.SAddr[2], bpfEvent.SAddr[3]),
					DAddr:     fmt.Sprintf("%d.%d.%d.%d", bpfEvent.DAddr[0], bpfEvent.DAddr[1], bpfEvent.DAddr[2], bpfEvent.DAddr[3]),
				}
			}()
		}
		select {
		case <-ctx.Done():
			close(stop)
			log.Logger.Info().Msg("stop consuming tcp events...")
			return
		default:
			read()
		}
	}
}
