package ebpf

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	errorspkg "errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/ddosify/alaz/cri"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/ebpf/proc"
	"github.com/ddosify/alaz/ebpf/tcp_state"
	"github.com/ddosify/alaz/log"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/mod/semver"
)

const (
	goTlsWriteSymbol = "crypto/tls.(*Conn).Write"
	goTlsReadSymbol  = "crypto/tls.(*Conn).Read"
	exeMaxSizeInMB   = 200
)

type BpfEvent interface {
	Type() string
}

type EbpfCollector struct {
	ctx            context.Context
	done           chan struct{}
	ebpfEvents     chan interface{}
	ebpfProcEvents chan interface{}
	ebpfTcpEvents  chan interface{}

	tlsAttachQueue chan uint32

	bpfPrograms map[string]Program

	sslWriteUprobes     map[uint32]link.Link
	sslReadEnterUprobes map[uint32]link.Link
	sslReadURetprobes   map[uint32]link.Link

	goTlsWriteUprobes   map[uint32]link.Link
	goTlsReadUprobes    map[uint32]link.Link
	goTlsReadUretprobes map[uint32][]link.Link // uprobes for ret instructions
	probesMu            sync.Mutex

	tlsPidMap map[uint32]struct{}
	mu        sync.Mutex

	ct *cri.CRITool
}

func NewEbpfCollector(parentCtx context.Context, ct *cri.CRITool) *EbpfCollector {
	ctx, _ := context.WithCancel(parentCtx)

	bpfPrograms := make(map[string]Program)

	// initialize bpfPrograms
	bpfPrograms["tcp_state_prog"] = tcp_state.InitTcpStateProg(nil)
	bpfPrograms["l7_prog"] = l7_req.InitL7Prog(nil)
	bpfPrograms["proc_prog"] = proc.InitProcProg(nil)

	return &EbpfCollector{
		ctx:                 ctx,
		done:                make(chan struct{}),
		ebpfEvents:          make(chan interface{}, 100000), // interface is 16 bytes, 16 * 100000 = 8 Megabytes
		ebpfProcEvents:      make(chan interface{}, 2000),
		ebpfTcpEvents:       make(chan interface{}, 1000),
		tlsPidMap:           make(map[uint32]struct{}),
		sslWriteUprobes:     make(map[uint32]link.Link),
		sslReadEnterUprobes: make(map[uint32]link.Link),
		sslReadURetprobes:   make(map[uint32]link.Link),
		goTlsWriteUprobes:   make(map[uint32]link.Link),
		goTlsReadUprobes:    make(map[uint32]link.Link),
		goTlsReadUretprobes: make(map[uint32][]link.Link),
		tlsAttachQueue:      make(chan uint32, 10),
		bpfPrograms:         bpfPrograms,
		ct:                  ct,
	}
}

func (e *EbpfCollector) Done() chan struct{} {
	return e.done
}

func (e *EbpfCollector) EbpfEvents() chan interface{} {
	return e.ebpfEvents
}

func (e *EbpfCollector) EbpfProcEvents() chan interface{} {
	return e.ebpfProcEvents
}

func (e *EbpfCollector) EbpfTcpEvents() chan interface{} {
	return e.ebpfTcpEvents
}

func (e *EbpfCollector) TlsAttachQueue() chan uint32 {
	return e.tlsAttachQueue
}

func (e *EbpfCollector) Init() {
	for _, p := range e.bpfPrograms {
		p.Load()
		p.Attach()
		p.InitMaps()
	}

	go func() {
		if e.ct == nil {
			log.Logger.Warn().Msg("cri tool is nil, skipping filtering container pids")
			return
		}
		tcpProg := e.bpfPrograms["tcp_state_prog"].(*tcp_state.TcpStateProg)
		t := time.NewTicker(30 * time.Second)

		for {
			select {
			case <-e.ctx.Done():
				t.Stop()
				return
			case <-t.C:
				pids, err := e.ct.GetPidsRunningOnContainers()
				if err != nil {
					log.Logger.Error().Err(err).Msg("error getting pids running on containers")
					continue
				}
				log.Logger.Debug().Msgf("got %d pids running on containers", len(pids))
				values := make([]uint8, len(pids))
				for i := range pids {
					values[i] = 1
				}
				err = tcpProg.PopulateContainerPidsMap(pids, values)
				if err != nil {
					log.Logger.Error().Err(err).Msg("error populating container pids map")
				}
			}
		}
	}()

	go func() {
		<-e.ctx.Done()
		e.close()
		close(e.done)
	}()
}

func (e *EbpfCollector) ListenEvents() {
	go e.bpfPrograms["tcp_state_prog"].Consume(e.ctx, e.ebpfTcpEvents)
	go e.bpfPrograms["l7_prog"].Consume(e.ctx, e.ebpfEvents)
	go e.bpfPrograms["proc_prog"].Consume(e.ctx, e.ebpfProcEvents)

	go e.AttachUprobesForEncrypted()
}

func (e *EbpfCollector) close() {
	log.Logger.Info().Msg("closing ebpf links")

	for _, p := range e.bpfPrograms {
		p.Close()
	}

	close(e.ebpfEvents)
	close(e.ebpfProcEvents)
	close(e.ebpfTcpEvents)

	e.probesMu.Lock()
	defer e.probesMu.Unlock()

	log.Logger.Info().Msg("closing ebpf uprobes")

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
	log.Logger.Info().Msg("ebpf collector closed")
}

// we check the size of the executable before reading it into memory
// because it can be very large
// otherwise we can get stuck to memory limit defined in k8s

// runs as one goroutine
func (e *EbpfCollector) AttachUprobesForEncrypted() {
	for pid := range e.tlsAttachQueue {
		// check duplicate
		e.mu.Lock()
		if _, ok := e.tlsPidMap[pid]; ok {
			e.mu.Unlock()
			continue
		}
		e.tlsPidMap[pid] = struct{}{}
		e.mu.Unlock()

		go func(pid uint32) {
			log.Logger.Debug().Str("ctx", "tls-uprobes").Uint32("pid", pid).Msg("attaching uprobes for encrypted connections")
			// attach to libssl uprobes if process is using libssl
			errs := e.AttachSslUprobesOnProcess("/proc", pid)
			if len(errs) > 0 {
				for _, err := range errs {
					if errorspkg.Is(err, fs.ErrNotExist) {
						// no such file or directory error
						// executable is not found,
						// it's probably a kernel thread, or a very short lived process
						continue
					}
					log.Logger.Debug().Err(err).Uint32("pid", pid).
						Msgf("error attaching ssl lib for pid: %d", pid)
				}
			}

			go_errs := e.AttachGoTlsUprobesOnProcess("/proc", pid)
			if len(go_errs) > 0 {
				for _, err := range go_errs {
					if errorspkg.Is(err, fs.ErrNotExist) {
						// no such file or directory error
						// executable is not found,
						// it's probably a kernel thread, or a very short lived process
						continue
					}
					log.Logger.Debug().Err(err).
						Msgf("error attaching go tls for pid: %d", pid)
				}
			}

		}(pid)
	}
}

func (e *EbpfCollector) AttachGoTlsUprobesOnProcess(procfs string, pid uint32) []error {
	path := fmt.Sprintf("%s/%d/exe", procfs, pid)
	errors := make([]error, 0)

	defer func() {
		if len(errors) > 0 {
			// close any uprobes that were attached
			e.probesMu.Lock()
			wr := e.goTlsWriteUprobes[pid]
			if wr != nil {
				wr.Close()
			}
			rd := e.goTlsReadUprobes[pid]
			if rd != nil {
				rd.Close()
			}

			// close any uretprobes that were attached
			for _, l := range e.goTlsReadUretprobes[pid] {
				l.Close()
			}
			e.probesMu.Unlock()
		}
	}()

	fileInfo, err := os.Stat(path)
	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error getting file info")
		errors = append(errors, err)
		return errors
	}

	if fileInfo.Size() > exeMaxSizeInMB*1024*1024 {
		log.Logger.Debug().Uint32("pid", pid).Msg("executable is too large, skipping")
		return errors
	}

	// read build info of a go executable
	bi, err := buildinfo.ReadFile(path)
	if err != nil {
		if strings.HasSuffix(err.Error(), "not a Go executable") || strings.Contains(err.Error(), "no such file or directory") {
			log.Logger.Debug().Str("reason", "gotls").Uint32("pid", pid).Msg("not a Go executable")
			return errors
		}
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error reading build info")
		errors = append(errors, err)
		return errors
	}

	// func arguments are stored in stack in go versions below 1.17
	// we need to get the stack pointer in order to read the arguments etc.
	// we only support reading arguments from registers for go versions >= 1.17
	if bi.GoVersion < "go1.17" {
		log.Logger.Debug().Str("reason", "gotls").Uint32("pid", pid).Str("version", bi.GoVersion).Msg("go version is below 1.17, skipping")
		return errors
	}

	// open in elf format in order to get the symbols
	ef, err := elf.Open(path)
	if err != nil {
		log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error opening executable")
		errors = append(errors, err)
		return errors
	}
	defer ef.Close()

	// nm command can be used to get the symbols as well
	symbols, err := ef.Symbols()
	if err != nil {
		if errorspkg.Is(err, elf.ErrNoSymbols) {
			log.Logger.Debug().Uint32("pid", pid).Msg("no symbols found")
			return errors
		}
		errors = append(errors, err)
		return errors
	}

	ex, err := link.OpenExecutable(path)
	if err != nil {
		log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error opening executable")
		errors = append(errors, err)
		return errors
	}

	for _, s := range symbols {
		if s.Name != goTlsWriteSymbol && s.Name != goTlsReadSymbol {
			continue
		}

		// find function address with cilium lib
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

				address = s.Value - prog.Vaddr + prog.Off
				break
			}
		}

		switch s.Name {
		case goTlsWriteSymbol:
			// &link.UprobeOptions{Address: address} is not necessary, we use it for efficiency
			// give address directly to uprobes, otherwise it will be calculated again
			// we calculate it here for uretprobes no matter what, because we need to attach uretprobes to ret instructions
			// and we need the address of the function
			// so in order to prevent Uprobe func to recalculating the address, we pass it here
			l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnWriteEnter, &link.UprobeOptions{Address: address})
			if err != nil {
				log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error attaching uprobe")
				errors = append(errors, err)
				return errors
			}
			e.probesMu.Lock()
			e.goTlsWriteUprobes[pid] = l
			e.probesMu.Unlock()
		case goTlsReadSymbol:
			l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnReadEnter, &link.UprobeOptions{Address: address})
			if err != nil {
				log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error attaching uprobe")
				errors = append(errors, err)
				return errors
			}
			e.probesMu.Lock()
			e.goTlsReadUprobes[pid] = l
			e.probesMu.Unlock()

			// when uretprobe is attached to a function, kernel overrides the return address on stack
			// with the address of the uretprobe
			// this messes up with go runtime and causes a crash
			// so we attach all ret instructions in the function as uprobes

			// .text section contains the instructions
			// in order to read the .text section of the executable
			// readelf or objdump can be used
			textSection := ef.Section(".text")
			if textSection == nil {
				log.Logger.Debug().Uint32("pid", pid).Msg("no .text section found")
				errors = append(errors, fmt.Errorf("no .text section found"))
				return errors
			}

			sStart := s.Value - textSection.Addr
			sEnd := sStart + s.Size

			sBytes := make([]byte, sEnd-sStart)
			readSeeker := textSection.Open()
			_, err = readSeeker.Seek(int64(sStart), io.SeekStart)
			if err != nil {
				log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error seeking to .text section")
				errors = append(errors, err)
				return errors
			}
			readBytes, err := readSeeker.Read(sBytes)
			if err != nil {
				log.Logger.Debug().Err(err).Uint32("pid", pid).Msg("error reading .text section")
				errors = append(errors, err)
				return errors
			}

			if readBytes != len(sBytes) {
				log.Logger.Debug().Uint32("pid", pid).Msg("error reading .text section")
				errors = append(errors, fmt.Errorf("error reading .text section"))
				return errors
			}

			returnOffsets := getReturnOffsets(ef.Machine, sBytes) // find all ret instructions in the function according to the architecture
			e.probesMu.Lock()
			e.goTlsReadUretprobes[pid] = make([]link.Link, 0)
			e.probesMu.Unlock()
			for _, offset := range returnOffsets {
				l, err := ex.Uprobe(s.Name, l7_req.L7BpfProgsAndMaps.GoTlsConnReadExit, &link.UprobeOptions{Address: address, Offset: uint64(offset)})
				if err != nil {
					log.Logger.Debug().Err(err).Str("reason", "gotls").Uint32("pid", pid).Msg("error attaching uretprobe")
					errors = append(errors, err)
					return errors
				}
				e.probesMu.Lock()
				e.goTlsReadUretprobes[pid] = append(e.goTlsReadUretprobes[pid], l)
				e.probesMu.Unlock()
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

	libsMap, err := parseSSLlib(toString(fileContent))
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
		log.Logger.Debug().Str("path", executablePath).Uint32("pid", pid).Str("version", version).Msgf("attaching ssl uprobes v3")

		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV3, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV3, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.1.0") >= 0 { // accept 1.1 as >= 1.1.1 for now, linking to 1.1.1 compatible uprobes
		log.Logger.Debug().Str("path", executablePath).Uint32("pid", pid).Str("version", version).Msgf("attaching ssl uprobes v1.1")

		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV111, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV111, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else if semver.Compare(version, "v1.0.2") >= 0 {
		log.Logger.Debug().Str("path", executablePath).Uint32("pid", pid).Str("version", version).Msgf("attaching ssl uprobes v1.0.2")
		sslWriteUprobe, err = ex.Uprobe("SSL_write", l7_req.L7BpfProgsAndMaps.SslWriteV102, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_write")
			return err
		}

		sslReadEnterUprobe, err = ex.Uprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslReadEnterV102, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uprobe", "SSL_read")
			return err
		}

		sslReadURetprobe, err = ex.Uretprobe("SSL_read", l7_req.L7BpfProgsAndMaps.SslRetRead, nil)
		if err != nil {
			log.Logger.Warn().Err(err).Msgf("error attaching %s uretprobe", "SSL_read")
			return err
		}
	} else {
		return fmt.Errorf("unsupported ssl version: %s", version)
	}

	e.probesMu.Lock()
	e.sslWriteUprobes[pid] = sslWriteUprobe
	e.sslReadEnterUprobes[pid] = sslReadEnterUprobe
	e.sslReadURetprobes[pid] = sslReadURetprobe
	e.probesMu.Unlock()

	log.Logger.Debug().Str("path", executablePath).Uint32("pid", pid).Msgf("successfully attached ssl uprobes")
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

// to avoid allocations
func toBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}
func toString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
