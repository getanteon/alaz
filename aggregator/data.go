package aggregator

// aggregate data from different sources
// 1. k8s
// 2. containerd (TODO)
// 3. ebpf
// 4. cgroup (TODO)
// 5. docker (TODO)

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/time/rate"

	"time"

	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/ebpf/proc"
	"github.com/ddosify/alaz/ebpf/tcp_state"
	"github.com/ddosify/alaz/log"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/ddosify/alaz/k8s"

	"github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/types"
)

type Aggregator struct {
	ctx context.Context

	// listen to events from different sources
	k8sChan             <-chan interface{}
	ebpfChan            <-chan interface{}
	ebpfProcChan        <-chan interface{}
	ebpfTcpChan         <-chan interface{}
	tlsAttachSignalChan chan uint32

	// store the service map
	clusterInfo *ClusterInfo

	// send data to datastore
	ds datastore.DataStore

	// http2 ch
	h2Mu     sync.RWMutex
	h2Ch     chan *l7_req.L7Event
	h2Frames map[string]*FrameArrival // pid-fd-streamId -> frame

	// postgres prepared stmt
	pgStmtsMu sync.RWMutex
	pgStmts   map[string]string // pid-fd-stmtname -> query

	h2ParserMu sync.RWMutex
	h2Parsers  map[string]*http2Parser // pid-fd -> http2Parser

	liveProcessesMu sync.RWMutex
	liveProcesses   map[uint32]struct{} // pid -> struct{}

	// Used to rate limit and drop trace events based on pid
	rateLimiters map[uint32]*rate.Limiter // pid -> rateLimiter
	rateLimitMu  sync.RWMutex

	// Used to find the correct mutex for the pid, some pids can share the same mutex
	muIndex atomic.Uint64
	muArray []*sync.RWMutex
}

// We need to keep track of the following
// in order to build find relationships between
// connections and pods/services

type SockInfo struct {
	Pid   uint32 `json:"pid"`
	Fd    uint64 `json:"fd"`
	Saddr string `json:"saddr"`
	Sport uint16 `json:"sport"`
	Daddr string `json:"daddr"`
	Dport uint16 `json:"dport"`
}

type http2Parser struct {
	// // Framer is the HTTP/2 framer to use.
	// framer *http2.Framer
	// // framer.ReadFrame() returns a frame, which is a struct

	// http2 request and response dynamic tables are separate
	// 2 decoders are needed
	// https://httpwg.org/specs/rfc7541.html#encoding.context
	clientHpackDecoder *hpack.Decoder
	serverHpackDecoder *hpack.Decoder
}

// type SocketMap
type SocketMap struct {
	mu *sync.RWMutex
	M  map[uint64]*SocketLine `json:"fdToSockLine"` // fd -> SockLine
}

type ClusterInfo struct {
	k8smu                 sync.RWMutex
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	// Pid -> SocketMap
	// pid -> fd -> {saddr, sport, daddr, dport}
	SocketMaps []*SocketMap // index symbolizes pid
}

// If we have information from the container runtimes
// we would have pid's of the containers within the pod
// and we can use that to find the podUid directly

// If we don't have the pid's of the containers
// we can use the following to find the podUid
// {saddr+sport} -> search in podIPToPodUid -> podUid
// {daddr+dport} -> search in serviceIPToServiceUid -> serviceUid
// or
// {daddr+dport} -> search in podIPToPodUid -> podUid

var (
	// default exponential backoff (*2)
	// when attemptLimit is increased, we are blocking the events that we wait it to be processed more
	retryInterval = 20 * time.Millisecond
	attemptLimit  = 3 // total attempt
	// 1st try - 20ms - 2nd try - 40ms - 3rd try

	defaultExpiration = 5 * time.Minute
	purgeTime         = 10 * time.Minute
)

var reverseDnsCache *cache.Cache
var re *regexp.Regexp

func init() {
	reverseDnsCache = cache.New(defaultExpiration, purgeTime)

	keywords := []string{"SELECT", "INSERT INTO", "UPDATE", "DELETE FROM", "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE TABLE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "CREATE INDEX", "DROP INDEX", "CREATE VIEW", "DROP VIEW", "GRANT", "REVOKE", "EXECUTE"}

	// Case-insensitive matching
	re = regexp.MustCompile(strings.Join(keywords, "|"))
}

func NewAggregator(parentCtx context.Context, k8sChan <-chan interface{},
	events chan interface{},
	procEvents chan interface{},
	tcpEvents chan interface{},
	tlsAttachSignalChan chan uint32,
	ds datastore.DataStore) *Aggregator {
	ctx, _ := context.WithCancel(parentCtx)
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
	}

	a := &Aggregator{
		ctx:                 ctx,
		k8sChan:             k8sChan,
		ebpfChan:            events,
		ebpfProcChan:        procEvents,
		ebpfTcpChan:         tcpEvents,
		clusterInfo:         clusterInfo,
		ds:                  ds,
		tlsAttachSignalChan: tlsAttachSignalChan,
		h2Ch:                make(chan *l7_req.L7Event, 1000000),
		h2Parsers:           make(map[string]*http2Parser),
		h2Frames:            make(map[string]*FrameArrival),
		liveProcesses:       make(map[uint32]struct{}),
		rateLimiters:        make(map[uint32]*rate.Limiter),
		pgStmts:             make(map[string]string),
		muIndex:             atomic.Uint64{},
		muArray:             nil,
	}

	maxPid, err := getPidMax()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error getting max pid")
	}
	sockMaps := make([]*SocketMap, maxPid+1) // index=pid
	// initialize sockMaps
	for i := range sockMaps {
		sockMaps[i] = &SocketMap{
			M:  nil, // initialized on demand later
			mu: nil,
		}
	}
	clusterInfo.SocketMaps = sockMaps

	a.getLiveProcesses()

	a.liveProcessesMu.RLock()
	countLiveProcesses := len(a.liveProcesses)
	a.liveProcessesMu.RUnlock()

	// normally, mutex per pid is straightforward solution
	// on regular systems, maxPid is around 32768
	// so, we allocate 32768 mutexes, which is 32768 * 24 bytes = 786KB
	// but on 64-bit systems, maxPid can be 4194304
	// and we don't want to allocate 4194304 mutexes, it adds up to 4194304 * 24 bytes = 100MB
	// So, some process will have to share the mutex

	// assume liveprocesses can increase up to 100 times of current count
	// if processes exceeds the count of mutex, they will share the mutex
	countMuArray := countLiveProcesses * 100
	if countMuArray > maxPid {
		countMuArray = maxPid
	}
	// for 2k processes, 200k mutex => 200k * 24 bytes = 4.80MB
	// in case of maxPid is 32678, 32678 * 24 bytes = 784KB, pick the smaller one
	a.muArray = make([]*sync.RWMutex, countMuArray)

	// set distinct mutex for every live process
	for pid := range a.liveProcesses {
		a.muIndex.Add(1)
		a.muArray[a.muIndex.Load()] = &sync.RWMutex{}
		sockMaps[pid].mu = a.muArray[a.muIndex.Load()]
		a.getAlreadyExistingSockets(pid)
	}

	go a.clearSocketLines(ctx)
	return a
}

func (a *Aggregator) getLiveProcesses() {
	// get all alive processes, populate liveProcesses
	cmd := exec.Command("ps", "-e", "-o", "pid=")
	output, err := cmd.Output()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error getting all alive processes")
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				pid := fields[0]
				pidInt, err := strconv.Atoi(pid)
				if err != nil {
					log.Logger.Error().Err(err).Msgf("error converting pid to int %s", pid)
					continue
				}
				a.liveProcesses[uint32(pidInt)] = struct{}{}
			}
		}
	}
}

func (a *Aggregator) Run() {
	go func() {
		// every 2 minutes, check alive processes, and clear the ones left behind
		// since we process events concurrently, some short-lived processes exit event can come before exec events
		// this causes zombie http2 workers

		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()

		for range t.C {
			a.liveProcessesMu.Lock()

			for pid, _ := range a.liveProcesses {
				// https://man7.org/linux/man-pages/man2/kill.2.html
				//    If sig is 0, then no signal is sent, but existence and permission
				//    checks are still performed; this can be used to check for the
				//    existence of a process ID or process group ID that the caller is
				//    permitted to signal.

				err := syscall.Kill(int(pid), 0)
				if err != nil {
					// pid does not exist
					delete(a.liveProcesses, pid)
					a.removeFromClusterInfo(pid)

					a.h2ParserMu.Lock()
					for key, parser := range a.h2Parsers {
						// h2Parsers  map[string]*http2Parser // pid-fd -> http2Parser
						if strings.HasPrefix(key, fmt.Sprint(pid)) {
							parser.clientHpackDecoder.Close()
							parser.serverHpackDecoder.Close()

							delete(a.h2Parsers, key)
						}
					}
					a.h2ParserMu.Unlock()

					a.rateLimitMu.Lock()
					delete(a.rateLimiters, pid)
					a.rateLimitMu.Unlock()

					a.pgStmtsMu.Lock()
					for key, _ := range a.pgStmts {
						if strings.HasPrefix(key, fmt.Sprint(pid)) {
							delete(a.pgStmts, key)
						}
					}
					a.pgStmtsMu.Unlock()
				}
			}

			a.liveProcessesMu.Unlock()
		}
	}()
	go a.processk8s()

	// TODO: determine the number of workers with benchmarking
	cpuCount := runtime.NumCPU()
	numWorker := 5 * cpuCount
	if numWorker < 50 {
		numWorker = 50 // min number
	}

	for i := 0; i < numWorker; i++ {
		go a.processEbpf(a.ctx)
		go a.processEbpfTcp(a.ctx)
		go a.processEbpfProc(a.ctx)
	}

	for i := 0; i < 2*cpuCount; i++ {
		go a.processHttp2Frames()
	}
}

func (a *Aggregator) processk8s() {
	for data := range a.k8sChan {
		d := data.(k8s.K8sResourceMessage)
		switch d.ResourceType {
		case k8s.POD:
			a.processPod(d)
		case k8s.SERVICE:
			a.processSvc(d)
		case k8s.REPLICASET:
			a.processReplicaSet(d)
		case k8s.DEPLOYMENT:
			a.processDeployment(d)
		case k8s.ENDPOINTS:
			a.processEndpoints(d)
		case k8s.CONTAINER:
			a.processContainer(d)
		case k8s.DAEMONSET:
			a.processDaemonSet(d)
		default:
			log.Logger.Warn().Msgf("unknown resource type %s", d.ResourceType)
		}
	}
}

func (a *Aggregator) processEbpfProc(ctx context.Context) {
	for data := range a.ebpfProcChan {
		select {
		case <-ctx.Done():
			return
		default:
			bpfEvent, ok := data.(ebpf.BpfEvent)
			if !ok {
				log.Logger.Error().Interface("ebpfData", data).Msg("error casting ebpf event")
				continue
			}
			switch bpfEvent.Type() {
			case proc.PROC_EVENT:
				d := data.(*proc.ProcEvent) // copy data's value
				if d.Type_ == proc.EVENT_PROC_EXEC {
					a.processExec(d)
				} else if d.Type_ == proc.EVENT_PROC_EXIT {
					a.processExit(d.Pid)
				}
			}
		}
	}
}

func (a *Aggregator) processEbpfTcp(ctx context.Context) {
	for data := range a.ebpfTcpChan {
		select {
		case <-ctx.Done():
			return
		default:
			bpfEvent, ok := data.(ebpf.BpfEvent)
			if !ok {
				log.Logger.Error().Interface("ebpfData", data).Msg("error casting ebpf event")
				continue
			}
			switch bpfEvent.Type() {
			case tcp_state.TCP_CONNECT_EVENT:
				d := data.(*tcp_state.TcpConnectEvent) // copy data's value
				a.processTcpConnect(d)
			}
		}
	}
}

func (a *Aggregator) processEbpf(ctx context.Context) {
	for data := range a.ebpfChan {
		select {
		case <-ctx.Done():
			return
		default:
			bpfEvent, ok := data.(ebpf.BpfEvent)
			if !ok {
				log.Logger.Error().Interface("ebpfData", data).Msg("error casting ebpf event")
				continue
			}
			switch bpfEvent.Type() {
			case l7_req.L7_EVENT:
				d := data.(*l7_req.L7Event) // copy data's value
				a.processL7(ctx, d)
			case l7_req.TRACE_EVENT:
				d := data.(*l7_req.TraceEvent)
				rateLimiter := a.getRateLimiterForPid(d.Pid)
				if rateLimiter.Allow() {
					a.ds.PersistTraceEvent(d)
				}
			}
		}
	}
}

func (a *Aggregator) getRateLimiterForPid(pid uint32) *rate.Limiter {
	var limiter *rate.Limiter
	a.rateLimitMu.RLock()
	limiter, ok := a.rateLimiters[pid]
	a.rateLimitMu.RUnlock()
	if !ok {
		a.rateLimitMu.Lock()
		// r means number of token added to bucket per second, maximum number of token in bucket is b, if bucket is full, token will be dropped
		// b means the initial and max number of token in bucket
		limiter = rate.NewLimiter(100, 1000)
		a.rateLimiters[pid] = limiter
		a.rateLimitMu.Unlock()
	}
	return limiter
}

func (a *Aggregator) processExec(d *proc.ProcEvent) {
	a.liveProcessesMu.Lock()
	defer a.liveProcessesMu.Unlock()

	a.liveProcesses[d.Pid] = struct{}{}

	// if duplicate exec event comes, underlying mutex will be changed
	// if first assigned mutex is locked and another exec event comes, mutex will be changed
	// and unlock of unlocked mutex now is a possibility
	// to avoid this case, if a socket map already has a mutex, don't change it
	if a.clusterInfo.SocketMaps[d.Pid].mu == nil {
		// create lock on demand
		a.muIndex.Add(1)
		a.muArray[(a.muIndex.Load())%uint64(len(a.muArray))] = &sync.RWMutex{}
		a.clusterInfo.SocketMaps[d.Pid].mu = a.muArray[(a.muIndex.Load())%uint64(len(a.muArray))]
	}
}

func (a *Aggregator) processExit(pid uint32) {
	a.liveProcessesMu.Lock()
	delete(a.liveProcesses, pid)
	a.removeFromClusterInfo(pid)
	a.liveProcessesMu.Unlock()

	a.h2ParserMu.Lock()
	pid_s := fmt.Sprint(pid)
	for key, parser := range a.h2Parsers {
		// h2Parsers  map[string]*http2Parser // pid-fd -> http2Parser
		if strings.HasPrefix(key, pid_s) {
			parser.clientHpackDecoder.Close()
			parser.serverHpackDecoder.Close()

			delete(a.h2Parsers, key)
		}
	}
	a.h2ParserMu.Unlock()

	a.rateLimitMu.Lock()
	delete(a.rateLimiters, pid)
	a.rateLimitMu.Unlock()

	a.pgStmtsMu.Lock()
	for key, _ := range a.pgStmts {
		if strings.HasPrefix(key, fmt.Sprint(pid)) {
			delete(a.pgStmts, key)
		}
	}
	a.pgStmtsMu.Unlock()
}

func (a *Aggregator) signalTlsAttachment(pid uint32) {
	a.tlsAttachSignalChan <- pid
}

func (a *Aggregator) processTcpConnect(d *tcp_state.TcpConnectEvent) {
	go a.signalTlsAttachment(d.Pid)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {

		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		var sockMap *SocketMap
		var ok bool

		sockMap = a.clusterInfo.SocketMaps[d.Pid]
		var skLine *SocketLine

		if sockMap.mu == nil {
			return
		}

		sockMap.mu.Lock() // lock for reading
		if sockMap.M == nil {
			sockMap.M = make(map[uint64]*SocketLine)
		}

		skLine, ok = sockMap.M[d.Fd]
		if !ok {
			skLine = NewSocketLine(d.Pid, d.Fd)
			sockMap.M[d.Fd] = skLine
		}

		skLine.AddValue(
			d.Timestamp, // get connection timestamp from ebpf
			&SockInfo{
				Pid:   d.Pid,
				Fd:    d.Fd,
				Saddr: d.SAddr,
				Sport: d.SPort,
				Daddr: d.DAddr,
				Dport: d.DPort,
			},
		)

		sockMap.mu.Unlock() // unlock for writing

	} else if d.Type_ == tcp_state.EVENT_TCP_CLOSED {
		var sockMap *SocketMap
		var ok bool

		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		sockMap = a.clusterInfo.SocketMaps[d.Pid]

		var skLine *SocketLine

		if sockMap.mu == nil {
			return
		}

		sockMap.mu.Lock() // lock for reading
		if sockMap.M == nil {
			sockMap.M = make(map[uint64]*SocketLine)
		}
		skLine, ok = sockMap.M[d.Fd]
		if !ok {
			sockMap.mu.Unlock() // unlock for reading
			return
		}
		sockMap.mu.Unlock() // unlock for reading

		// If connection is established before, add the close event
		skLine.AddValue(
			d.Timestamp, // get connection close timestamp from ebpf
			nil,         // closed
		)

		connKey := a.getConnKey(d.Pid, d.Fd)

		// remove h2Parser if exists
		a.h2ParserMu.Lock()
		h2Parser, ok := a.h2Parsers[connKey]
		if ok {
			h2Parser.clientHpackDecoder.Close()
			h2Parser.serverHpackDecoder.Close()
		}
		delete(a.h2Parsers, connKey)
		a.h2ParserMu.Unlock()

		// remove pgStmt if exists
		a.pgStmtsMu.Lock()
		for key, _ := range a.pgStmts {
			if strings.HasPrefix(key, connKey) {
				delete(a.pgStmts, key)
			}
		}
		a.pgStmtsMu.Unlock()

	}
}

func parseHttpPayload(request string) (method string, path string, httpVersion string, hostHeader string) {
	// Find the first space character
	lines := strings.Split(request, "\n")
	parts := strings.Split(lines[0], " ")
	if len(parts) >= 3 {
		method = parts[0]
		path = parts[1]
		httpVersion = parts[2]
	}

	for _, line := range lines[1:] {
		// find Host header
		if strings.HasPrefix(line, "Host:") {
			hostParts := strings.Split(line, " ")
			if len(hostParts) >= 2 {
				hostHeader = hostParts[1]
				hostHeader = strings.TrimSuffix(hostHeader, "\r")
				break
			}
		}
	}

	return method, path, httpVersion, hostHeader
}

type FrameArrival struct {
	ClientHeadersFrameArrived bool
	ServerHeadersFrameArrived bool
	ServerDataFrameArrived    bool
	event                     *l7_req.L7Event // l7 event that carries server data frame
	req                       *datastore.Request

	statusCode uint32
	grpcStatus uint32
}

func (a *Aggregator) processHttp2Frames() {
	createFrameKey := func(pid uint32, fd uint64, streamId uint32) string {
		return fmt.Sprintf("%d-%d-%d", pid, fd, streamId)
	}

	done := make(chan bool, 1)

	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()

		for {
			select {
			case <-t.C:
				a.h2Mu.Lock()
				for key, f := range a.h2Frames {
					if f.ClientHeadersFrameArrived && !f.ServerHeadersFrameArrived {
						delete(a.h2Frames, key)
					} else if !f.ClientHeadersFrameArrived && f.ServerHeadersFrameArrived {
						delete(a.h2Frames, key)
					}
				}
				a.h2Mu.Unlock()
			case <-done:
				return
			}
		}
	}()

	persistReq := func(d *l7_req.L7Event, req *datastore.Request, statusCode uint32, grpcStatus uint32) {
		if req.Method == "" || req.Path == "" {
			// if we couldn't parse the request, discard
			// this is possible because of hpack dynamic table, we can't parse the request until a new connection is established

			// TODO: check if duplicate processing happens for the same request at some point on processing
			// magic message can be used to identify the connection on ebpf side
			// when adjustment is made on ebpf side, we can remove this check
			return
		}

		skInfo := a.findRelatedSocket(a.ctx, d)
		if skInfo == nil {
			return
		}

		req.Latency = d.WriteTimeNs - req.Latency
		req.StartTime = d.EventReadTime
		req.Completed = true
		req.FromIP = skInfo.Saddr
		req.ToIP = skInfo.Daddr
		req.Tls = d.Tls
		req.FromPort = skInfo.Sport
		req.ToPort = skInfo.Dport
		req.FailReason = ""
		if req.Protocol == "" {
			req.Protocol = "HTTP2"
			if req.Tls {
				req.Protocol = "HTTPS"
			}
			req.StatusCode = statusCode
		} else if req.Protocol == "gRPC" {
			req.StatusCode = grpcStatus
		}

		// toUID is set to :authority header in client frame
		err := a.setFromTo(skInfo, d, req, req.ToUID)
		if err != nil {
			return
		}

		if d.WriteTimeNs < req.Latency {
			// ignore
			return
		}

		a.ds.PersistRequest(req)
	}

	parseFrameHeader := func(buf []byte) http2.FrameHeader {
		// http2/frame.go/readFrameHeader
		// to avoid copy op, we read the frame header manually here
		return http2.FrameHeader{
			Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
			Type:     http2.FrameType(buf[3]),
			Flags:    http2.Flags(buf[4]),
			StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
		}
	}

	for d := range a.h2Ch {
		// Normally we tried to use http2.Framer to parse frames but
		// http2.Framer spends too much memory and cpu reading frames
		// golang.org/x/net/http2.(*Framer).ReadFrame /go/pkg/mod/golang.org/x/net@v0.12.0/http2/frame.go:505
		// golang.org/x/net/http2.NewFramer.func2 /go/pkg/mod/golang.org/x/net@v0.12.0/http2/frame.go:444
		// getReadBuf is called for every ReadFrame call and allocates a new buffer
		// Additionally, later on io.ReadFull is called to copy the frame to the buffer
		// both cpu and memory intensive ops

		// framer := http2.NewFramer(nil, bytes.NewReader(d.Payload[0:d.PayloadSize]))
		// framer.SetReuseFrames()

		buf := d.Payload[:d.PayloadSize]
		fd := d.Fd
		var offset uint32 = 0

		a.h2ParserMu.RLock()
		h2Parser := a.h2Parsers[a.getConnKey(d.Pid, d.Fd)]
		a.h2ParserMu.RUnlock()
		if h2Parser == nil {
			a.h2ParserMu.Lock()
			h2Parser = &http2Parser{
				clientHpackDecoder: hpack.NewDecoder(4096, nil),
				serverHpackDecoder: hpack.NewDecoder(4096, nil),
			}
			a.h2Parsers[a.getConnKey(d.Pid, d.Fd)] = h2Parser
			a.h2ParserMu.Unlock()
		}

		// parse frame
		// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1
		if d.Method == l7_req.CLIENT_FRAME {
			for {
				// can be multiple frames in the payload

				// http2/frame.go/readFrameHeader
				// to avoid copy op, we read the frame header manually here

				if len(buf)-int(offset) < 9 {
					break
				}

				fh := parseFrameHeader(buf[offset:])

				// frame header consists of 9 bytes
				offset += 9

				endOfFrame := offset + fh.Length
				// since we read constant 1024 bytes from the kernel
				// we need to check left over bytes are enough to read
				if len(buf) < int(endOfFrame) {
					break
				}

				// skip if not headers frame
				if fh.Type != http2.FrameHeaders {
					offset = endOfFrame
					continue
				}

				streamId := fh.StreamID
				key := createFrameKey(d.Pid, fd, streamId)
				a.h2Mu.Lock()
				if _, ok := a.h2Frames[key]; !ok {
					a.h2Frames[key] = &FrameArrival{
						ClientHeadersFrameArrived: true,
						req:                       &datastore.Request{},
					}
				}

				fa := a.h2Frames[key]
				fa.ClientHeadersFrameArrived = true
				fa.req.Latency = d.WriteTimeNs // set latency to write time here, will be updated later

				// Process client headers frame
				reqHeaderSet := func(req *datastore.Request) func(hf hpack.HeaderField) {
					return func(hf hpack.HeaderField) {
						switch hf.Name {
						case ":method":
							if req.Method == "" {
								req.Method = hf.Value
							}
						case ":path":
							if req.Path == "" {
								req.Path = hf.Value
							}
						case ":authority":
							if req.ToUID == "" {
								req.ToUID = hf.Value
							}
						case "content-type":
							if req.Protocol == "" {
								if strings.HasPrefix(hf.Value, "application/grpc") {
									req.Protocol = "gRPC"
								}
							}
						}
					}
				}
				h2Parser.clientHpackDecoder.SetEmitFunc(reqHeaderSet(fa.req))

				// if ReadFrame were used, f.HeaderBlockFragment()
				h2Parser.clientHpackDecoder.Write(buf[offset:endOfFrame])

				offset = endOfFrame

				if fa.ServerHeadersFrameArrived {
					req := *fa.req
					go persistReq(d, &req, fa.statusCode, fa.grpcStatus)
					delete(a.h2Frames, key)
				}
				a.h2Mu.Unlock()
				break
			}
		} else if d.Method == l7_req.SERVER_FRAME {
			for {
				if len(buf)-int(offset) < 9 {
					break
				}
				// can be multiple frames in the payload
				fh := parseFrameHeader(buf[offset:])
				offset += 9

				endOfFrame := offset + fh.Length
				// since we read constant 1024 bytes from the kernel
				// we need to check left over bytes are enough to read
				if len(buf) < int(endOfFrame) {
					break
				}

				streamId := fh.StreamID
				key := createFrameKey(d.Pid, fd, streamId)

				if fh.Type != http2.FrameHeaders {
					offset = endOfFrame
					continue
				}

				if fh.Type == http2.FrameHeaders {
					a.h2Mu.Lock()
					if _, ok := a.h2Frames[key]; !ok {
						a.h2Frames[key] = &FrameArrival{
							ServerHeadersFrameArrived: true,
							req:                       &datastore.Request{},
						}
					}
					fa := a.h2Frames[key]
					fa.ServerHeadersFrameArrived = true
					// Process server headers frame
					respHeaderSet := func(req *datastore.Request) func(hf hpack.HeaderField) {
						return func(hf hpack.HeaderField) {
							switch hf.Name {
							case ":status":
								s, _ := strconv.Atoi(hf.Value)
								fa.statusCode = uint32(s)
							case "grpc-status":
								s, _ := strconv.Atoi(hf.Value)
								fa.grpcStatus = uint32(s)
							}
						}
					}
					h2Parser.serverHpackDecoder.SetEmitFunc(respHeaderSet(fa.req))
					h2Parser.serverHpackDecoder.Write(buf[offset:endOfFrame])

					if fa.ClientHeadersFrameArrived {
						req := *fa.req
						go persistReq(d, &req, fa.statusCode, fa.grpcStatus)
						delete(a.h2Frames, key)
					}
					a.h2Mu.Unlock()
					break
				}
			}
		} else {
			log.Logger.Error().Msg("unknown http2 frame type")
			continue
		}
	}

	done <- true // signal cleaning goroutine
}

func (a *Aggregator) getPodWithIP(addr string) (types.UID, bool) {
	a.clusterInfo.k8smu.RLock() // lock for reading
	podUid, ok := a.clusterInfo.PodIPToPodUid[addr]
	a.clusterInfo.k8smu.RUnlock() // unlock for reading
	return podUid, ok
}

func (a *Aggregator) getSvcWithIP(addr string) (types.UID, bool) {
	a.clusterInfo.k8smu.RLock() // lock for reading
	svcUid, ok := a.clusterInfo.ServiceIPToServiceUid[addr]
	a.clusterInfo.k8smu.RUnlock() // unlock for reading
	return svcUid, ok
}

func (a *Aggregator) setFromTo(skInfo *SockInfo, d *l7_req.L7Event, reqDto *datastore.Request, hostHeader string) error {
	// find pod info
	podUid, ok := a.getPodWithIP(skInfo.Saddr)
	if !ok {
		return fmt.Errorf("error finding pod with sockets saddr")
	}

	reqDto.FromUID = string(podUid)
	reqDto.FromType = "pod"
	reqDto.FromPort = skInfo.Sport
	reqDto.ToPort = skInfo.Dport

	// find service info
	svcUid, ok := a.getSvcWithIP(skInfo.Daddr)
	if ok {
		reqDto.ToUID = string(svcUid)
		reqDto.ToType = "service"
	} else {
		podUid, ok := a.getPodWithIP(skInfo.Daddr)

		if ok {
			reqDto.ToUID = string(podUid)
			reqDto.ToType = "pod"
		} else {
			// 3rd party url
			if hostHeader != "" {
				reqDto.ToUID = hostHeader
				reqDto.ToType = "outbound"
			} else {
				remoteDnsHost, err := getHostnameFromIP(skInfo.Daddr)
				if err == nil {
					// dns lookup successful
					reqDto.ToUID = remoteDnsHost
					reqDto.ToType = "outbound"
				} else {
					reqDto.ToUID = skInfo.Daddr
					reqDto.ToType = "outbound"
				}
			}
		}
	}

	return nil
}

func (a *Aggregator) getConnKey(pid uint32, fd uint64) string {
	return fmt.Sprintf("%d-%d", pid, fd)
}

func (a *Aggregator) processL7(ctx context.Context, d *l7_req.L7Event) {
	// other protocols events come as whole, but http2 events come as frames
	// we need to aggregate frames to get the whole request
	defer func() {
		if r := recover(); r != nil {
			// TODO: we need to fix this properly
			log.Logger.Debug().Msgf("probably a http2 frame sent on a closed chan: %v", r)
		}
	}()

	if d.Protocol == l7_req.L7_PROTOCOL_HTTP2 {
		var ok bool

		a.liveProcessesMu.RLock()
		_, ok = a.liveProcesses[d.Pid]
		a.liveProcessesMu.RUnlock()
		if !ok {
			return // if a late event comes, do not create parsers and new worker to avoid memory leak
		}

		a.h2Ch <- d
		return
	}

	var path string
	if d.Protocol == l7_req.L7_PROTOCOL_POSTGRES {
		// parse sql command from payload
		// path = sql command
		// method = sql message type
		var err error
		path, err = a.parseSqlCommand(d)
		if err != nil {
			log.Logger.Error().AnErr("err", err)
			return
		}
	}

	skInfo := a.findRelatedSocket(ctx, d)
	if skInfo == nil {
		log.Logger.Debug().Uint32("pid", d.Pid).
			Uint64("fd", d.Fd).Uint64("writeTime", d.WriteTimeNs).
			Str("protocol", d.Protocol).Uint32("payloadSize", d.PayloadSize).Any("payload", string(d.Payload[:d.PayloadSize])).Msg("socket not found")
		return
	}

	reqDto := datastore.Request{
		StartTime:  d.EventReadTime,
		Latency:    d.Duration,
		FromIP:     skInfo.Saddr,
		ToIP:       skInfo.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Tid:        d.Tid,
		Seq:        d.Seq,
	}

	// Since we process events concurrently
	// TCP events and L7 events can be processed out of order

	var reqHostHeader string
	// parse http payload, extract path, query params, headers
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP {
		_, path, _, reqHostHeader = parseHttpPayload(string(d.Payload[0:d.PayloadSize]))
	}

	err := a.setFromTo(skInfo, d, &reqDto, reqHostHeader)
	if err != nil {
		return
	}

	reqDto.Path = path
	reqDto.Completed = !d.Failed

	// In AMQP-DELIVER event, we are capturing from read syscall,
	// exchange sockets
	// In Alaz context, From is always the one that makes the write
	// and To is the one that makes the read
	if d.Protocol == l7_req.L7_PROTOCOL_AMQP && d.Method == l7_req.DELIVER {
		reqDto.FromIP, reqDto.ToIP = reqDto.ToIP, reqDto.FromIP
		reqDto.FromPort, reqDto.ToPort = reqDto.ToPort, reqDto.FromPort
		reqDto.FromUID, reqDto.ToUID = reqDto.ToUID, reqDto.FromUID
		reqDto.FromType, reqDto.ToType = reqDto.ToType, reqDto.FromType
	}

	if d.Protocol == l7_req.L7_PROTOCOL_HTTP && d.Tls {
		reqDto.Protocol = "HTTPS"
	}

	err = a.ds.PersistRequest(&reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}

}

// reverse dns lookup
func getHostnameFromIP(ipAddr string) (string, error) {
	// return from cache, if exists
	// consumes too much memory otherwise
	if host, ok := reverseDnsCache.Get(ipAddr); ok {
		return host.(string), nil
	} else {
		addrs, err := net.LookupAddr(ipAddr)
		if err != nil {
			return "", err
		}

		// The reverse DNS lookup can return multiple names for the same IP.
		// In this example, we return the first name found.
		if len(addrs) > 0 {
			reverseDnsCache.Set(ipAddr, addrs[0], 0)
			return addrs[0], nil
		}
		return "", fmt.Errorf("no hostname found for IP address: %s", ipAddr)
	}
}

// get all tcp sockets for the pid
// iterate through all sockets
// create a new socket line for each socket
// add it to the socket map
func (a *Aggregator) getAlreadyExistingSockets(pid uint32) {
	// no need for locking because this is called firstmost and no other goroutine is running

	socks := map[string]sock{}
	sockMap := a.fetchSocketMap(pid)

	// Get the sockets for the process.
	var err error
	for _, f := range []string{"tcp", "tcp6"} {
		sockPath := strings.Join([]string{"/proc", fmt.Sprint(pid), "net", f}, "/")

		ss, err := readSockets(sockPath)
		if err != nil {
			continue
		}

		for _, s := range ss {
			socks[s.Inode] = sock{TcpSocket: s}
		}
	}

	// Get the file descriptors for the process.
	fdDir := strings.Join([]string{"/proc", fmt.Sprint(pid), "fd"}, "/")
	fdEntries, err := os.ReadDir(fdDir)
	if err != nil {
		return
	}

	fds := make([]Fd, 0, len(fdEntries))
	for _, entry := range fdEntries {
		fd, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			continue
		}
		dest, err := os.Readlink(path.Join(fdDir, entry.Name()))
		if err != nil {
			continue
		}
		var socketInode string
		if strings.HasPrefix(dest, "socket:[") && strings.HasSuffix(dest, "]") {
			socketInode = dest[len("socket:[") : len(dest)-1]
		}
		fds = append(fds, Fd{Fd: fd, Dest: dest, SocketInode: socketInode})
	}

	// Match the sockets to the file descriptors.
	for _, fd := range fds {
		if fd.SocketInode != "" {
			// add to values
			s := socks[fd.SocketInode].TcpSocket
			sockInfo := &SockInfo{
				Pid:   pid,
				Fd:    fd.Fd,
				Saddr: s.SAddr.IP().String(),
				Sport: s.SAddr.Port(),
				Daddr: s.DAddr.IP().String(),
				Dport: s.DAddr.Port(),
			}

			if sockInfo.Saddr == "zero IP" || sockInfo.Daddr == "zero IP" || sockInfo.Sport == 0 || sockInfo.Dport == 0 {
				continue
			}

			skLine := NewSocketLine(pid, fd.Fd)
			skLine.AddValue(0, sockInfo)

			if sockMap.mu == nil {
				return
			}

			sockMap.mu.Lock()
			if sockMap.M == nil {
				sockMap.M = make(map[uint64]*SocketLine)
			}
			sockMap.M[fd.Fd] = skLine
			sockMap.mu.Unlock()
		}
	}

}

func (a *Aggregator) fetchSkInfo(ctx context.Context, skLine *SocketLine, d *l7_req.L7Event) *SockInfo {
	rc := attemptLimit
	rt := retryInterval
	var skInfo *SockInfo
	var err error

	for {
		skInfo, err = skLine.GetValue(d.WriteTimeNs)
		if err == nil && skInfo != nil {
			break
		}
		// log.Logger.Debug().Err(err).Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTime", d.WriteTimeNs).Msg("retry to get skInfo...")
		rc--
		if rc == 0 {
			break
		}
		time.Sleep(rt)
		rt *= 2 // exponential backoff

		select {
		case <-ctx.Done():
			log.Logger.Debug().Msg("processL7 exiting, stop retrying...")
			return nil
		default:
			continue
		}
	}

	return skInfo
}

func (a *Aggregator) removeFromClusterInfo(pid uint32) {
	sockMap := a.clusterInfo.SocketMaps[pid]
	if sockMap.mu == nil {
		return
	}
	sockMap.mu.Lock()
	sockMap.M = nil
	sockMap.mu.Unlock()
}

func (a *Aggregator) fetchSocketMap(pid uint32) *SocketMap {
	sockMap := a.clusterInfo.SocketMaps[pid]

	if sockMap.mu == nil {
		return nil
	}

	sockMap.mu.Lock()
	if sockMap.M == nil {
		sockMap.M = make(map[uint64]*SocketLine)
	}
	sockMap.mu.Unlock()

	return sockMap
}

func (a *Aggregator) findRelatedSocket(ctx context.Context, d *l7_req.L7Event) *SockInfo {
	sockMap := a.clusterInfo.SocketMaps[d.Pid]
	// acquire sockMap lock

	if sockMap.mu == nil {
		return nil
	}

	sockMap.mu.Lock()

	if sockMap.M == nil {
		sockMap.M = make(map[uint64]*SocketLine)
	}

	skLine, ok := sockMap.M[d.Fd]
	if !ok {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Msg("error finding skLine, go look for it")
		// start new socket line, find already established connections
		skLine = NewSocketLine(d.Pid, d.Fd)
		sockMap.M[d.Fd] = skLine
	}

	// release sockMap lock
	sockMap.mu.Unlock()

	skInfo := a.fetchSkInfo(ctx, skLine, d)
	if skInfo == nil {
		return nil
	}

	return skInfo
}

func (a *Aggregator) parseSqlCommand(d *l7_req.L7Event) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	if d.Method == l7_req.SIMPLE_QUERY {
		// Q, 4 bytes of length, sql command

		// skip Q, (simple query)
		r = r[1:]

		// skip 4 bytes of length
		r = r[4:]

		// get sql command
		sqlCommand = string(r)

		// garbage data can come for postgres, we need to filter out
		// search statement for sql keywords like
		if !containsSQLKeywords(sqlCommand) {
			return "", fmt.Errorf("no sql command found")
		}
	} else if d.Method == l7_req.EXTENDED_QUERY { // prepared statement
		// Parse or Bind message
		id := r[0]
		switch id {
		case 'P':
			// 1 byte P
			// 4 bytes len
			// prepared statement name(str) (null terminated)
			// query(str) (null terminated)
			// parameters
			var stmtName string
			var query string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 3 {
				stmtName = string(vars[0])
				query = string(vars[1])
			} else if len(vars) == 2 { // query too long for our buffer
				stmtName = string(vars[0])
				query = string(vars[1]) + "..."
			} else {
				return "", fmt.Errorf("could not parse 'parse' frame for postgres")
			}

			a.pgStmtsMu.Lock()
			a.pgStmts[a.getPgStmtKey(d.Pid, d.Fd, stmtName)] = query
			a.pgStmtsMu.Unlock()
			return fmt.Sprintf("PREPARE %s AS %s", stmtName, query), nil
		case 'B':
			// 1 byte B
			// 4 bytes len
			// portal str (null terminated)
			// prepared statement name str (null terminated)
			// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BIND

			var stmtName string
			vars := bytes.Split(r[5:], []byte{0})
			if len(vars) >= 2 {
				stmtName = string(vars[1])
			} else {
				return "", fmt.Errorf("could not parse bind frame for postgres")
			}

			a.pgStmtsMu.RLock()
			query, ok := a.pgStmts[a.getPgStmtKey(d.Pid, d.Fd, stmtName)]
			a.pgStmtsMu.RUnlock()
			if !ok || query == "" { // we don't have the query for the prepared statement
				// Execute (name of prepared statement) [(parameter)]
				return fmt.Sprintf("EXECUTE %s *values*", stmtName), nil
			}
			return query, nil
		default:
			return "", fmt.Errorf("could not parse extended query for postgres")
		}
	} else if d.Method == l7_req.CLOSE_OR_TERMINATE {
		sqlCommand = string(r)
	}

	return sqlCommand, nil
}

func (a *Aggregator) getPgStmtKey(pid uint32, fd uint64, stmtName string) string {
	return fmt.Sprintf("%s-%s", a.getConnKey(pid, fd), stmtName)
}

// Check if a string contains SQL keywords
func containsSQLKeywords(input string) bool {
	return re.MatchString(strings.ToUpper(input))
}

func (a *Aggregator) sendOpenConnection(sl *SocketLine) {
	sl.mu.RLock()
	defer sl.mu.RUnlock()

	if len(sl.Values) == 0 {
		return
	}

	// values are sorted by timestamp
	// get the last value
	// if it is a socket open, send it to the datastore
	// if it is a socket close, ignore it

	t := sl.Values[len(sl.Values)-1]
	if t.SockInfo != nil {
		podUid, ok := a.getPodWithIP(t.SockInfo.Saddr)
		if !ok {
			// ignore if source pod not found, or it is not a pod
			return
		}

		ac := &datastore.AliveConnection{
			CheckTime: time.Now().UnixMilli(),
			FromIP:    t.SockInfo.Saddr,
			FromType:  "pod",
			FromUID:   string(podUid),
			FromPort:  t.SockInfo.Sport,
			ToIP:      t.SockInfo.Daddr,
			ToType:    "",
			ToUID:     "",
			ToPort:    t.SockInfo.Dport,
		}

		// find destination pod or service
		svcUid, ok := a.getSvcWithIP(t.SockInfo.Daddr)
		if ok {
			ac.ToType = "service"
			ac.ToUID = string(svcUid)
		} else {
			podUid, ok := a.getPodWithIP(t.SockInfo.Daddr)
			if ok {
				ac.ToUID = string(podUid)
				ac.ToType = "pod"
			} else {
				ac.ToType = "outbound"
				ac.ToUID = t.SockInfo.Daddr
			}
		}

		a.ds.PersistAliveConnection(ac)
	}
}

func (a *Aggregator) clearSocketLines(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	skLineCh := make(chan *SocketLine, 1000)

	go func() {
		// spawn N goroutines to clear socket map
		for i := 0; i < 10; i++ {
			go func() {
				for skLine := range skLineCh {
					// send open connections to datastore
					a.sendOpenConnection(skLine)
					// clear socket history
					skLine.DeleteUnused()
				}
			}()
		}
	}()

	for range ticker.C {
		for _, sockMap := range a.clusterInfo.SocketMaps {
			if sockMap.mu == nil {
				continue
			}
			sockMap.mu.Lock()
			if sockMap.M != nil {
				for _, skLine := range sockMap.M {
					skLineCh <- skLine
				}
			}
			sockMap.mu.Unlock()
		}
	}
}

func getPidMax() (int, error) {
	// Read the contents of the file
	f, err := os.Open("/proc/sys/kernel/pid_max")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return 0, err
	}
	content, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return 0, err
	}

	// Convert the content to an integer
	pidMax, err := strconv.Atoi(string(content[:len(content)-1])) // trim newline
	if err != nil {
		fmt.Println("Error converting to integer:", err)
		return 0, err
	}
	return pidMax, nil
}
