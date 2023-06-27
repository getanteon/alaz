package ebpf

import (
	"alaz/ebpf/l7_req"
	"alaz/ebpf/tcp_state"
	"alaz/log"
	"os"
	"time"
)

// TODO: type
var EbpfEvents chan interface{}

type BpfEvent interface {
	Type() string
}

func init() {
	EbpfEvents = make(chan interface{}, 1000) // TODO: make configurable
}

func Deploy() {
	go tcp_state.Deploy(EbpfEvents)
	go l7_req.Deploy(EbpfEvents)

	go listenDebugMsgs()
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
