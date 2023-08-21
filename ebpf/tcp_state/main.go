package tcp_state

import (
	"context"
	"fmt"
	"os"
	"time"
	"unsafe"

	"alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
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
type TcpEvent struct {
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

// returns when program is detached
func DeployAndWait(parentCtx context.Context, ch chan interface{}) {
	ctx, _ := context.WithCancel(parentCtx)
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

	ticker := time.NewTicker(1 * time.Millisecond)
	defer ticker.Stop()

	time.Sleep(1 * time.Second)

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.bpfPrograms.InetSockSetState, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link inet_sock_set_state tracepoint")
	}
	defer func() {
		log.Logger.Info().Msg("closing inet_sock_set_state tracepoint")
		l.Close()
	}()

	l1, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_connect tracepoint")
	}
	defer func() {
		log.Logger.Info().Msg("closing sys_enter_connect tracepoint")
		l1.Close()
	}()

	l2, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_connect tracepoint")
	}
	defer func() {
		log.Logger.Info().Msg("closing sys_exit_connect tracepoint")
		l2.Close()
	}()

	// initialize perf event readers
	tcpListenEvents, err := perf.NewReader(objs.TcpListenEvents, 64*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}
	defer func() {
		log.Logger.Info().Msg("closing tcpListenEvents perf event reader")
		tcpListenEvents.Close()
	}()

	tcpConnectEvents, err := perf.NewReader(objs.TcpConnectEvents, 64*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}
	defer func() {
		log.Logger.Info().Msg("closing tcpConnectEvents perf event reader")
		tcpConnectEvents.Close()
	}()

	// go listenDebugMsgs()

	readDone := make(chan struct{})
	go func() {
		for {
			read := func() {
				record, err := tcpConnectEvents.Read()
				if err != nil {
					log.Logger.Warn().Err(err).Msg("error reading from perf array")
				}

				if record.LostSamples != 0 {
					log.Logger.Warn().Msgf("lost samples tcp-connect %d", record.LostSamples)
				}

				if record.RawSample == nil || len(record.RawSample) == 0 {
					return
				}

				bpfEvent := (*TcpEvent)(unsafe.Pointer(&record.RawSample[0]))

				go func() {
					ch <- TcpConnectEvent{
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
			case <-readDone:
				return
			default:
				read()
			}

		}
	}()

	<-ctx.Done() // wait for context to be cancelled
	readDone <- struct{}{}
	// defers will clean up
}

func listenDebugMsgs() {
	printsPath := "/sys/kernel/debug/tracing/trace_pipe"

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fd, err := os.Open(printsPath)
	if err != nil {
		log.Logger.Warn().Err(err).Msg("error opening trace_pipe")
	}
	defer fd.Close()

	buf := make([]byte, 1024)
	for range ticker.C {
		n, err := fd.Read(buf)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error reading from trace_pipe")
		}
		log.Logger.Info().Msgf("read %d bytes: %s\n", n, buf[:n])
	}
}
