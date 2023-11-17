package proc

import (
	"context"
	"time"
	"unsafe"

	"github.com/ddosify/alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf proc.c -- -I../headers

type PExitEvent struct {
	Pid uint32
}

const PEXIT_EVENT = "process_exit_event"

func (e PExitEvent) Type() string {
	return PEXIT_EVENT
}

var objs bpfObjects

func LoadBpfObjects() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	objs = bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}
}

// returns when program is detached
func DeployAndWait(parentCtx context.Context, ch chan interface{}) {
	ctx, _ := context.WithCancel(parentCtx)
	defer objs.Close()

	time.Sleep(1 * time.Second)

	l, err := link.Tracepoint("sched", "sched_process_exit", objs.bpfPrograms.SchedProcessExit, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sched_process_exit tracepoint")
	}
	defer func() {
		log.Logger.Info().Msg("closing sched_process_exit tracepoint")
		l.Close()
	}()

	pExitEvents, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating ringbuf reader")
	}
	defer func() {
		log.Logger.Info().Msg("closing pExitEvents ringbuf reader")
		pExitEvents.Close()
	}()

	// go listenDebugMsgs()

	readDone := make(chan struct{})
	go func() {
		for {
			read := func() {
				record, err := pExitEvents.Read()
				if err != nil {
					log.Logger.Warn().Err(err).Msg("error reading from pExitEvents")
				}

				bpfEvent := (*PExitEvent)(unsafe.Pointer(&record.RawSample[0]))

				go func() {
					// log.Logger.Warn().Msgf("pid %d exited", bpfEvent.Pid)
					ch <- *bpfEvent
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
