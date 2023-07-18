// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package l7_req

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// match with values in l7_req.c
const (
	BPF_L7_PROTOCOL_UNKNOWN = iota
	BPF_L7_PROTOCOL_HTTP
	BPF_L7_PROTOCOL_RABBITMQ
)

// for user space
const (
	L7_PROTOCOL_HTTP     = "L7_PROTOCOL_HTTP"
	L7_PROTOCOL_RABBITMQ = "L7_PROTOCOL_RABBITMQ"
	L7_PROTOCOL_UNKNOWN  = "L7_PROTOCOL_UNKNOWN"
)

// Custom type for the enumeration
type L7ProtocolConversion uint32

// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_HTTP:
		return L7_PROTOCOL_HTTP
	case BPF_L7_PROTOCOL_RABBITMQ:
		return L7_PROTOCOL_RABBITMQ
	case BPF_L7_PROTOCOL_UNKNOWN:
		return L7_PROTOCOL_UNKNOWN
	default:
		return "Unknown"
	}
}

// match with values in l7_req.c, order is important
const (
	BPF_METHOD_UNKNOWN = iota
	BPF_METHOD_GET
	BPF_METHOD_POST
	BPF_METHOD_PUT
	BPF_METHOD_PATCH
	BPF_METHOD_DELETE
	BPF_METHOD_HEAD
	BPF_METHOD_CONNECT
	BPF_METHOD_OPTIONS
	BPF_METHOD_TRACE
)

// match with values in l7_req.c, order is important
const (
	BPF_RABBIT_METHOD_UNKNOWN = iota
	BPF_RABBIT_METHOD_PRODUCE
	BPF_RABBIT_METHOD_CONSUME
)

// Custom type for the enumeration
type RabbitMQMethodConversion uint32

// String representation of the enumeration values
func (e RabbitMQMethodConversion) String() string {
	switch e {
	case BPF_RABBIT_METHOD_PRODUCE:
		return PRODUCE
	case BPF_RABBIT_METHOD_CONSUME:
		return CONSUME
	default:
		return "Unknown"
	}
}

// for http, user space
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	PATCH   = "PATCH"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	CONNECT = "CONNECT"
	OPTIONS = "OPTIONS"
	TRACE   = "TRACE"
)

// for rabbitmq, user space
const (
	PRODUCE = "PRODUCE"
	CONSUME = "CONSUME"
)

// Custom type for the enumeration
type HTTPMethodConversion uint32

// String representation of the enumeration values
func (e HTTPMethodConversion) String() string {
	switch e {
	case BPF_METHOD_GET:
		return GET
	case BPF_METHOD_POST:
		return POST
	case BPF_METHOD_PUT:
		return PUT
	case BPF_METHOD_PATCH:
		return PATCH
	case BPF_METHOD_DELETE:
		return DELETE
	case BPF_METHOD_HEAD:
		return HEAD
	case BPF_METHOD_CONNECT:
		return CONNECT
	case BPF_METHOD_OPTIONS:
		return OPTIONS
	case BPF_METHOD_TRACE:
		return TRACE
	default:
		return "Unknown"
	}
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf l7.c -- -I../headers

const mapKey uint32 = 0

// for user space
type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Method              string
	Payload             [512]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
}

const L7_EVENT = "l7_event"

func (e L7Event) Type() string {
	return L7_EVENT
}

func Deploy(ch chan interface{}) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}
	defer objs.Close()

	// pinning a ebpf program
	// err := objs.bpfPrograms.GetCommand.Pin("/sys/fs/bpf/kprobe_execve_command")
	// if err != nil {
	// 	log.Default().Printf("could not pin program, %v", err)
	// }

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	time.Sleep(1 * time.Second)

	l, err := link.Tracepoint("syscalls", "sys_enter_read", objs.bpfPrograms.SysEnterRead, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_read tracepoint")
	}
	defer l.Close()
	fmt.Println("sys_enter_read linked")

	l1, err := link.Tracepoint("syscalls", "sys_enter_write", objs.bpfPrograms.SysEnterWrite, nil)
	if err != nil {
		log.Logger.Debug().Str("verifier log", string(objs.bpfPrograms.SysEnterWrite.VerifierLog)).Msg("verifier log")
		log.Logger.Fatal().Err(err).Msg("link sys_enter_write tracepoint")
	}
	fmt.Println("sys_enter_write linked")
	defer l1.Close()

	l2, err := link.Tracepoint("syscalls", "sys_exit_read", objs.bpfPrograms.SysExitRead, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_read tracepoint")
	}
	fmt.Println("sys_exit_read linked")
	defer l2.Close()

	l3, err := link.Tracepoint("syscalls", "sys_enter_sendto", objs.bpfPrograms.SysEnterSendto, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_sendto tracepoint")
	}
	fmt.Println("sys_enter_sendto linked")
	defer l3.Close()

	l4, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", objs.bpfPrograms.SysEnterRecvfrom, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_recvfrom tracepoint")
	}
	fmt.Println("sys_enter_recvfrom linked")
	defer l4.Close()

	l5, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", objs.bpfPrograms.SysExitRecvfrom, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_recvfrom tracepoint")
	}
	fmt.Println("sys_exit_recvfrom linked")
	defer l5.Close()

	// initialize perf event readers
	l7Events, err := perf.NewReader(objs.L7Events, 64*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.

	go func() {
		for {
			record, err := l7Events.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost samples l7-event %d", record.LostSamples)
			}

			// TODO: investigate why this is happening
			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Warn().Msgf("read sample l7-event nil or empty")
				continue
			}

			l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

			go func() {

				protocol := L7ProtocolConversion(l7Event.Protocol).String()
				var method string
				switch protocol {
				case L7_PROTOCOL_HTTP:
					method = HTTPMethodConversion(l7Event.Method).String()
				case L7_PROTOCOL_RABBITMQ:
					method = RabbitMQMethodConversion(l7Event.Method).String()
				default:
					method = "Unknown"
				}

				// TODO: remove this
				if protocol == L7_PROTOCOL_RABBITMQ {
					log.Logger.Info().Str("method", method).
						Uint32("pid", l7Event.Pid).
						Str("payload", string(l7Event.Payload[:l7Event.PayloadSize])).
						Msg("rabbitmq method")
				}

				ch <- L7Event{
					Fd:                  l7Event.Fd,
					Pid:                 l7Event.Pid,
					Status:              l7Event.Status,
					Duration:            l7Event.Duration,
					Protocol:            protocol,
					Method:              method,
					Payload:             l7Event.Payload,
					PayloadSize:         l7Event.PayloadSize,
					PayloadReadComplete: uint8ToBool(l7Event.PayloadReadComplete),
					Failed:              uint8ToBool(l7Event.Failed),
					WriteTimeNs:         l7Event.WriteTimeNs,
				}
			}()

		}
	}()

	select {}
}

// 0 is false, 1 is true
func uint8ToBool(num uint8) bool {
	return num != 0
}
