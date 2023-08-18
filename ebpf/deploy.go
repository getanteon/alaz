package ebpf

import (
	"alaz/ebpf/l7_req"
	"alaz/ebpf/tcp_state"
	"alaz/log"
	"context"
	"os"
	"sync"
	"time"
)

type BpfEvent interface {
	Type() string
}

type EbpfCollector struct {
	ctx        context.Context
	done       chan struct{}
	ebpfEvents chan interface{}
}

func NewEbpfCollector(parentCtx context.Context) *EbpfCollector {
	ctx, _ := context.WithCancel(parentCtx)

	return &EbpfCollector{
		ctx:        ctx,
		done:       make(chan struct{}),
		ebpfEvents: make(chan interface{}, 100000),
	}
}

func (e *EbpfCollector) Done() chan struct{} {
	return e.done
}

func (e *EbpfCollector) EbpfEvents() chan interface{} {
	return e.ebpfEvents
}

func (e *EbpfCollector) Deploy() {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		tcp_state.DeployAndWait(e.ctx, e.ebpfEvents)
	}()
	go func() {
		defer wg.Done()
		l7_req.DeployAndWait(e.ctx, e.ebpfEvents)
	}()
	wg.Wait()

	log.Logger.Info().Msg("ebpf programs exited")
	close(e.done)

	// go listenDebugMsgs()
}

func listenDebugMsgs() {
	printsPath := "/sys/kernel/debug/tracing/trace_pipe"

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fd, err := os.Open(printsPath)
	if err != nil {
		log.Logger.Warn().Err(err).Msg("error opening trace_pipe to listen for ebpf debug messages")
	}
	defer fd.Close()

	buf := make([]byte, 1024)
	for range ticker.C {
		n, err := fd.Read(buf)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error reading from trace_pipe")
		}
		log.Logger.Info().Msgf("%s\n", buf[:n])
	}
}
