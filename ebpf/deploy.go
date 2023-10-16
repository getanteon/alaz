package ebpf

import (
	"context"
	"debug/elf"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/ebpf/tcp_state"
	"github.com/ddosify/alaz/log"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/mod/semver"
)

type PidLocks struct {
	locks map[uint32]*sync.Mutex
}

func NewPidLocks() *PidLocks {
	return &PidLocks{
		locks: make(map[uint32]*sync.Mutex),
	}
}

func (p *PidLocks) Lock(pid uint32) {
	lock, ok := p.locks[pid]
	if !ok {
		lock = &sync.Mutex{}
		p.locks[pid] = lock
	}
	lock.Lock()
}

func (p *PidLocks) Release(pid uint32) {
	lock, ok := p.locks[pid]
	if !ok {
		return
	}
	lock.Unlock()
}

const (
	goTlsWriteSymbol = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol  = "crypto/tls.(*Conn).Read"
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

	goTlsWriteUprobes map[uint32]link.Link
	goTlsReadUprobes  map[uint32]link.Link

	goTlsReadUretprobes map[uint32][]link.Link // uprobes for ret instructions

	tlsPidMap map[uint32]struct{}
	pidLocks  *PidLocks
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
		goTlsWriteUprobes:   make(map[uint32]link.Link),
		goTlsReadUprobes:    make(map[uint32]link.Link),
		goTlsReadUretprobes: make(map[uint32][]link.Link),
		pidLocks:            NewPidLocks(),
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
			// number, err := strconv.ParseUint(queryParam, 10, 32)
			// if err != nil {
			// 	http.Error(w, "Invalid query parameter 'number'", http.StatusBadRequest)
			// 	return
			// }
			// pid := uint32(number)

			// errors := e.AddSSLLibPid("/proc", pid)
			// if errors != nil {
			// 	for _, err := range errors {
			// 		log.Logger.Error().Err(err).Uint32("pid", pid).
			// 			Msgf("error attaching ssl lib for pid: %d", pid)
			// 	}
			// 	http.Error(w, errors[0].Error(), http.StatusInternalServerError)
			// 	return
			// }
		},
	)

	// load programs and convert them to user space structs
	tcp_state.LoadBpfObjects()
	l7_req.LoadBpfObjects()

	// function to version to program

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
	for pid := range e.goTlsWriteUprobes {
		e.goTlsWriteUprobes[pid].Close()
	}
	for pid := range e.goTlsReadUprobes {
		e.goTlsReadUprobes[pid].Close()
	}
	for pid := range e.goTlsReadUretprobes {
		for _, l := range e.goTlsReadUretprobes[pid] {
			l.Close()
		}
	}
}

func (e *EbpfCollector) ListenForEncryptedReqs(pid uint32) {
	if _, ok := e.tlsPidMap[pid]; ok {
		log.Logger.Debug().Msgf("pid: %d already attached for tls", pid)
		return
	}

	e.pidLocks.Lock(pid)
	defer e.pidLocks.Release(pid)

	// attach to libssl uprobes if process is using libssl
	errors := e.AttachSslUprobesOnProcess("/proc", pid)
	if errors != nil && len(errors) > 0 {
		for _, err := range errors {
			log.Logger.Error().Err(err).Uint32("pid", pid).
				Msgf("error attaching ssl lib for pid: %d", pid)
		}
	}

	// if process is go, attach to go tls
	go_errs := e.AttachGoTlsUprobesOnProcess("/proc", pid)
	if go_errs != nil && len(go_errs) > 0 {
		for _, err := range go_errs {
			log.Logger.Error().Err(err).Uint32("pid", pid).
				Msgf("error attaching go tls for pid: %d", pid)
		}
	}

	e.tlsPidMap[pid] = struct{}{}
}

func (e *EbpfCollector) AttachGoTlsUprobesOnProcess(procfs string, pid uint32) []error {
	path := fmt.Sprintf("%s/%d/exe", procfs, pid)

	// open in elf format in order to get the symbols
	ef, err := elf.Open(path)
	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error opening executable")
		return []error{err}
	}

	// nm command can be used to get the symbols as well
	symbols, err := ef.Symbols()
	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error reading symbols")
		return []error{err}
	}

	// .text section contains the instructions
	// in order to read the .text section of the executable
	// readelf or objdump can be used
	textSection := ef.Section(".text")
	if textSection == nil {
		log.Logger.Debug().Uint32("pid", pid).Msg("no .text section found")
		return nil
	}
	textSectionData, err := textSection.Data()
	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error reading .text section")
		return nil
	}
	// textSectionLen := uint64(len(textSectionData) - 1)

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error opening executable")
		return []error{err}
	}

	for _, s := range symbols {
		if s.Name != goTlsWriteSymbol && s.Name != goTlsReadSymbol {
			continue
		}

		switch s.Name {
		case goTlsWriteSymbol:
			// &link.UprobeOptions{Address: address}
			l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnWriteEnter, nil)
			if err != nil {
				log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error attaching uprobe")
				return nil
			}
			e.goTlsWriteUprobes[pid] = l
		case goTlsReadSymbol:
			l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnReadEnter, nil)
			if err != nil {
				log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error attaching uprobe")
				return nil
			}
			e.goTlsReadUprobes[pid] = l

			// when uretprobe is attached to a function, kernel overrides the return address on stack
			// with the address of the uretprobe
			// this messes up with go runtime and causes a crash
			// so we attach all ret instructions in the function as uprobes

			// find read functions address with cilium lib

			address := s.Value
			// find the address that will be used to attach uprobes
			for _, prog := range ef.Progs {
				// Skip uninteresting segments.
				if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
					continue
				}

				if prog.Vaddr <= s.Value && s.Value < (prog.Vaddr+prog.Memsz) {
					// If the symbol value is contained in the segment, calculate
					// the symbol offset.
					//
					// fn symbol offset = fn symbol VA - .text VA + .text offset
					//
					// stackoverflow.com/a/40249502

					// fmt.Printf("gotlsx got from symbol %s s.Value %d prog.Vaddr: %d prog.Off %d\n", s.Name, s.Value, prog.Vaddr, prog.Off)

					address = s.Value - prog.Vaddr + prog.Off
					break
				}
			}

			sStart := s.Value - textSection.Addr
			sEnd := sStart + s.Size

			sBytes := textSectionData[sStart:sEnd]
			// TODO: check if empty
			returnOffsets := getReturnOffsets(ef.Machine, sBytes) // find all ret instructions in the function according to the architecture
			e.goTlsReadUretprobes[pid] = make([]link.Link, 0)
			for _, offset := range returnOffsets {
				l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnReadExit, &link.UprobeOptions{Address: address, Offset: uint64(offset)})
				if err != nil {
					return nil // TODO: return error
				}
				e.goTlsReadUretprobes[pid] = append(e.goTlsReadUretprobes[pid], l)
				log.Logger.Debug().Str("reason", "gotls").Uint32("pid", pid).Msgf("attached uretprobe to %s at offset %d", s.Name, offset)
			}
		}
	}

	return nil
}

func (t *EbpfCollector) AttachSslUprobesOnProcess(procfs string, pid uint32) []error {
	errors := make([]error, 0)
	sslLibs, err := findSSLExecutablesByPid(procfs, pid)

	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error finding ssl lib")
		return errors
	}

	if len(sslLibs) == 0 {
		log.Logger.Info().Uint32("pid", pid).Msg("no ssl lib found")
		return errors
	}

	for _, sslLib := range sslLibs {
		err = t.AttachSSlUprobes(pid, sslLib.path, sslLib.version)
		if err != nil {
			log.Logger.Error().Err(err).Str("path", sslLib.path).Str("version", sslLib.version).Msgf("error attaching ssl uprobes")
			errors = append(errors, err)
		}
	}

	return errors
}

func findSSLExecutablesByPid(procfs string, pid uint32) (map[string]*sslLib, error) {
	// look for memory mapping of the process
	file, err := os.Open(fmt.Sprintf("%s/%d/maps", procfs, pid))
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileContent, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	libsMap, err := parseSSLlib(string(fileContent))
	if err != nil {
		return nil, err
	}

	for libPath, _ := range libsMap {
		fullpath := fmt.Sprintf("%s/%d/root%s", procfs, pid, libPath)

		// modify parsed path to match the full path
		if _, err := os.Stat(fullpath); os.IsNotExist(err) {
			delete(libsMap, libPath)
		} else {
			l := libsMap[libPath]
			l.path = fullpath
		}
	}

	// key : parsed path
	// value : full path and version
	return libsMap, nil
}

func (e *EbpfCollector) AttachSSlUprobes(pid uint32, executablePath string, version string) error {
	ex, err := link.OpenExecutable(executablePath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error opening executable %s", executablePath)
		return err
	}

	var sslWriteUprobe, sslReadEnterUprobe, sslReadURetprobe link.Link

	if semver.Compare(version, "v3.0.0") >= 0 {
		log.Logger.Info().Str("path", executablePath).Uint32("pid", pid).Str("version", version).Msgf("attaching ssl uprobes v3")

		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV3, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV3, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.1.0") >= 0 { // accept 1.1 as >= 1.1.1 for now, linking to 1.1.1 compatible uprobes
		log.Logger.Info().Str("path", executablePath).Uint32("pid", pid).Str("version", version).Msgf("attaching ssl uprobes v1.1")

		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV111, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV111, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.0.2") >= 0 {
		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV102, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV102, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else {
		return fmt.Errorf("unsupported ssl version: %s", version)
	}

	e.sslWriteUprobes[pid] = sslWriteUprobe
	e.sslReadEnterUprobes[pid] = sslReadEnterUprobe
	e.sslReadURetprobes[pid] = sslReadURetprobe

	log.Logger.Info().Str("path", executablePath).Uint32("pid", pid).Msgf("successfully attached ssl uprobes")
	return nil
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

func getReturnOffsets(machine elf.Machine, instructions []byte) []int {
	var res []int
	switch machine {
	case elf.EM_X86_64:
		for i := 0; i < len(instructions); {
			ins, err := x86asm.Decode(instructions[i:], 64)
			if err == nil && ins.Op == x86asm.RET {
				res = append(res, i)
			}
			i += ins.Len
		}
	case elf.EM_AARCH64:
		for i := 0; i < len(instructions); {
			ins, err := arm64asm.Decode(instructions[i:])
			if err == nil && ins.Op == arm64asm.RET {
				res = append(res, i)
			}
			i += 4
		}
	}
	return res
}
