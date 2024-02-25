package proc

import (
	"context"
	"os"
	"unsafe"

	"github.com/ddosify/alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/linux"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	BPF_EVENT_PROC_EXEC = iota + 1
	BPF_EVENT_PROC_EXIT
)

const (
	EVENT_PROC_EXEC = "EVENT_PROC_EXEC"
	EVENT_PROC_EXIT = "EVENT_PROC_EXIT"
)

// Custom type for the enumeration
type ProcEventConversion uint32

// String representation of the enumeration values
func (e ProcEventConversion) String() string {
	switch e {
	case BPF_EVENT_PROC_EXEC:
		return EVENT_PROC_EXEC
	case BPF_EVENT_PROC_EXIT:
		return EVENT_PROC_EXIT
	default:
		return "Unknown"
	}
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf proc.c -- -I../headers

type PEvent struct {
	Pid   uint32
	Type_ uint8
	_     [3]byte
}

type ProcEvent struct {
	Pid   uint32
	Type_ string
}

const PROC_EVENT = "proc_event"

func (e ProcEvent) Type() string {
	return PROC_EVENT
}

var objs bpfObjects

type ProcProgConfig struct {
	ProcEventsMapSize uint32 // specified in terms of os page size
}

var defaultConfig *ProcProgConfig = &ProcProgConfig{
	ProcEventsMapSize: 16,
}

type ProcProg struct {
	// links represent a program attached to a hook
	links             map[string]link.Link // key : hook name
	ProcEvents        *perf.Reader
	ProcEventsMapSize uint32
}

func InitProcProg(conf *ProcProgConfig) *ProcProg {
	if conf == nil {
		conf = defaultConfig
	}

	return &ProcProg{
		links:             map[string]link.Link{},
		ProcEventsMapSize: conf.ProcEventsMapSize,
	}
}

func (pp *ProcProg) Close() {
	for hookName, link := range pp.links {
		log.Logger.Info().Msgf("unattach %s", hookName)
		link.Close()
	}
	objs.Close()
}

// Loads bpf programs into kernel
func (pp *ProcProg) Load() {
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
func (pp *ProcProg) Attach() {
	l, err := link.Tracepoint("sched", "sched_process_exit", objs.bpfPrograms.SchedProcessExit, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sched_process_exit tracepoint")
	}
	pp.links["sched/sched_process_exit"] = l

	l1, err := link.Tracepoint("sched", "sched_process_exec", objs.bpfPrograms.SchedProcessExec, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sched_process_exec tracepoint")
	}
	pp.links["sched/sched_process_exec"] = l1
}

func (pp *ProcProg) InitMaps() {
	var err error
	pp.ProcEvents, err = perf.NewReader(objs.ProcEvents, 16*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating ringbuf reader")
	}
}

func (pp *ProcProg) Consume(ctx context.Context, ch chan interface{}) {
	for {
		read := func() {
			record, err := pp.ProcEvents.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from proc events map")
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Debug().Msgf("read sample l7-event nil or empty")
				return
			}

			bpfEvent := (*PEvent)(unsafe.Pointer(&record.RawSample[0]))

			go func() {
				ch <- &ProcEvent{
					Pid:   bpfEvent.Pid,
					Type_: ProcEventConversion(bpfEvent.Type_).String(),
				}
			}()
		}

		select {
		case <-ctx.Done():
			return
		default:
			read()
		}
	}
}
