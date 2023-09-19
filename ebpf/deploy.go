package ebpf

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
)

type BpfEvent interface {
	Type() string
}

type EbpfCollector struct {
	ctx        context.Context
	done       chan struct{}
	ebpfEvents chan interface{}

	// TODO: objectify l7_req and tcp_state

	sslWriteUprobes     map[uint32]link.Link
	sslReadEnterUprobes map[uint32]link.Link
	sslReadURetprobes   map[uint32]link.Link

	tlsPidMap map[uint32]struct{}
}

func NewEbpfCollector(parentCtx context.Context) *EbpfCollector {
	ctx, _ := context.WithCancel(parentCtx)

	return &EbpfCollector{
		ctx:                 ctx,
		done:                make(chan struct{}),
		ebpfEvents:          make(chan interface{}, 100000),
		tlsPidMap:           make(map[uint32]struct{}),
		sslWriteUprobes:     make(map[uint32]link.Link),
		sslReadEnterUprobes: make(map[uint32]link.Link),
		sslReadURetprobes:   make(map[uint32]link.Link),
	}
}

func (e *EbpfCollector) Done() chan struct{} {
	return e.done
}

func (e *EbpfCollector) EbpfEvents() chan interface{} {
	return e.ebpfEvents
}

func (e *EbpfCollector) Deploy() {
	http.HandleFunc("/attach-ssl-write",
		func(w http.ResponseWriter, r *http.Request) {
			queryParam := r.URL.Query().Get("number")
			if queryParam == "" {
				http.Error(w, "Missing query parameter 'number'", http.StatusBadRequest)
				return
			}
			number, err := strconv.ParseUint(queryParam, 10, 32)
			if err != nil {
				http.Error(w, "Invalid query parameter 'number'", http.StatusBadRequest)
				return
			}
			pid := uint32(number)

			err = e.AddSSLLibPid("/proc", pid)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		},
	)

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

func (e *EbpfCollector) close() {
	close(e.ebpfEvents)

	for pid := range e.sslWriteUprobes {
		e.sslWriteUprobes[pid].Close()
	}
	for pid := range e.sslReadEnterUprobes {
		e.sslReadEnterUprobes[pid].Close()
	}
	for pid := range e.sslReadURetprobes {
		e.sslReadURetprobes[pid].Close()
	}
}

func (e *EbpfCollector) ListenForTlsReqs(pid uint32) {
	if _, ok := e.tlsPidMap[pid]; ok {
		log.Logger.Warn().Msgf("pid: %d already attached for tls", pid)
		return
	}
	err := e.AddSSLLibPid("/proc", pid)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error attaching ssl lib for pid: %d", pid)
		return
	}
	log.Logger.Info().Msgf("attached ssl lib for pid: %d", pid)
	e.tlsPidMap[pid] = struct{}{}
}

func (t *EbpfCollector) AddSSLLibPid(procfs string, pid uint32) error {
	sslLibrary, err := findSSLLibraryByPid(procfs, pid)

	if err != nil {
		log.Logger.Warn().Err(err).Msg("error finding ssl lib")
		return nil
	} else {
		log.Logger.Info().Str("path", sslLibrary).Uint32("pid", pid).Msg("found libssl shared object")
	}

	// TODO: add version check to attach different uprobes for different versions
	// currently we only support openssl 1.1.1

	err = t.AttachSSlUprobes(pid, sslLibrary)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error attaching ssl uprobes")
		return err
	}

	return nil
}

func (e *EbpfCollector) AttachSSlUprobes(pid uint32, executablePath string) error {
	ex, err := link.OpenExecutable(executablePath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error opening executable %s", executablePath)
		return err
	}

	sslWriteUprobe, err := ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV11, nil)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
		return err
	}
	e.sslWriteUprobes[pid] = sslWriteUprobe

	sslReadEnterUprobe, err := ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV11, nil)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
		return err
	}
	e.sslReadEnterUprobes[pid] = sslReadEnterUprobe

	sslReadURetprobe, err := ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
		return err
	}
	e.sslReadURetprobes[pid] = sslReadURetprobe

	return nil
}

func findSSLLibraryByPid(procfs string, pid uint32) (string, error) {
	libName := "libssl.so"
	// look for memory mapping of the process
	file, err := os.Open(fmt.Sprintf("%s/%d/maps", procfs, pid))

	if err != nil {
		return "", err
	}

	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())

		if len(parts) <= 5 {
			continue
		}

		libPath := parts[5]

		if libName != "" && !strings.Contains(libPath, libName) {
			continue
		}

		fullpath := fmt.Sprintf("%s/%d/root%s", procfs, pid, libPath)

		// check if the file exists
		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			continue
		}

		return fullpath, nil
	}

	return "", fmt.Errorf("openssl lib not found for pid: %d", pid)
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
