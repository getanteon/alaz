package aggregator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/time/rate"

	"time"

	"github.com/ddosify/alaz/aggregator/kafka"
	"github.com/ddosify/alaz/cri"
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

const (
	POD      = "pod"
	SVC      = "service"
	OUTBOUND = "outbound"
)

const (
	KAFKA = "kafka" // LOG_CONTEXT_KEY should match
	REDIS = "redis"
)

type Aggregator struct {
	ctx context.Context
	ct  *cri.CRITool

	// listen to events from different sources
	k8sChan             chan interface{}
	ebpfChan            chan interface{}
	ebpfProcChan        chan interface{}
	ebpfTcpChan         chan interface{}
	tlsAttachSignalChan chan uint32

	// store the service map
	clusterInfo *ClusterInfo

	// send data to datastore
	ds datastore.DataStore

	// http2 ch
	h2Mu     sync.RWMutex
	h2Ch     chan *l7_req.L7Event
	h2Frames map[string]*FrameArrival // pid-fd-streamId -> frame

	h2ParserMu sync.RWMutex
	h2Parsers  map[string]*http2Parser // pid-fd -> http2Parser

	// postgres prepared stmt
	pgStmtsMu sync.RWMutex
	pgStmts   map[string]string // pid-fd-stmtname -> query

	// postgres prepared stmt
	mySqlStmtsMu sync.RWMutex
	mySqlStmts   map[string]string // pid-fd-stmtId -> query

	liveProcessesMu sync.RWMutex
	liveProcesses   map[uint32]struct{} // pid -> struct{}

	// Used to rate limit and drop trace events based on pid
	rateLimiters map[uint32]*rate.Limiter // pid -> rateLimiter
	rateLimitMu  sync.RWMutex
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
var maxPid int

func init() {
	reverseDnsCache = cache.New(defaultExpiration, purgeTime)

	keywords := []string{"SELECT", "INSERT INTO", "UPDATE", "DELETE FROM", "CREATE TABLE", "ALTER TABLE", "DROP TABLE", "TRUNCATE TABLE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "CREATE INDEX", "DROP INDEX", "CREATE VIEW", "DROP VIEW", "GRANT", "REVOKE", "EXECUTE"}

	// Case-insensitive matching
	re = regexp.MustCompile(strings.Join(keywords, "|"))

	var err error
	maxPid, err = getPidMax()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error getting max pid")
	}
}

func NewAggregator(parentCtx context.Context, ct *cri.CRITool, k8sChan chan interface{},
	events chan interface{},
	procEvents chan interface{},
	tcpEvents chan interface{},
	tlsAttachSignalChan chan uint32,
	ds datastore.DataStore) *Aggregator {

	ctx, _ := context.WithCancel(parentCtx)

	a := &Aggregator{
		ctx:          ctx,
		ct:           ct,
		k8sChan:      k8sChan,
		ebpfChan:     events,
		ebpfProcChan: procEvents,
		ebpfTcpChan:  tcpEvents,
		// clusterInfo:         clusterInfo,
		ds:                  ds,
		tlsAttachSignalChan: tlsAttachSignalChan,
		h2Ch:                make(chan *l7_req.L7Event, 1000000),
		h2Parsers:           make(map[string]*http2Parser),
		h2Frames:            make(map[string]*FrameArrival),
		liveProcesses:       make(map[uint32]struct{}),
		rateLimiters:        make(map[uint32]*rate.Limiter),
		pgStmts:             make(map[string]string),
		mySqlStmts:          make(map[string]string),
	}

	var err error
	a.liveProcesses, err = ct.GetPidsRunningOnContainers()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("could not get running containers")
	}

	a.liveProcessesMu.RLock()
	liveProcCount := len(a.liveProcesses)
	a.liveProcessesMu.RUnlock()

	a.clusterInfo = newClusterInfo(liveProcCount)

	go a.clearSocketLines(ctx)

	go func() {
		t := time.NewTicker(2 * time.Minute)

		for range t.C {
			log.Logger.Debug().
				Int("ebpfChan-lag", len(a.ebpfChan)).
				Int("ebpfTcpChan-lag", len(a.ebpfTcpChan)).
				Msg("lag of channels")
		}
	}()

	return a
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
					delete(a.liveProcesses, pid)
					a.processExit(pid)
				}
			}

			a.liveProcessesMu.Unlock()
		}
	}()
	go a.processk8s()

	cpuCount := runtime.NumCPU()
	numWorker := cpuCount

	for i := 0; i < numWorker; i++ {
		go a.processEbpfTcp(a.ctx)
		go a.processEbpfProc(a.ctx)
	}

	for i := 0; i < 4*cpuCount; i++ {
		go a.processEbpf(a.ctx)
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
		case k8s.STATEFULSET:
			a.processStatefulSet(d)
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
				ctxPid := context.WithValue(a.ctx, log.LOG_CONTEXT, fmt.Sprint(d.Pid))
				a.processTcpConnect(ctxPid, d)
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
				ctxPid := context.WithValue(a.ctx, log.LOG_CONTEXT, fmt.Sprint(d.Pid))
				go a.signalTlsAttachment(d.Pid)
				a.processL7(ctxPid, d)
				// dist tracing disabled by default temporarily
				// case l7_req.TRACE_EVENT:
				// 	d := data.(*l7_req.TraceEvent)
				// 	rateLimiter := a.getRateLimiterForPid(d.Pid)
				// 	if rateLimiter.Allow() {
				// 		a.ds.PersistTraceEvent(d)
				// 	}
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
	a.liveProcesses[d.Pid] = struct{}{}
	a.liveProcessesMu.Unlock()

	a.clusterInfo.SignalSocketMapCreation(d.Pid)
}

func (a *Aggregator) processExit(pid uint32) {
	a.clusterInfo.clearProc(pid)

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

	a.mySqlStmtsMu.Lock()
	for key, _ := range a.pgStmts {
		if strings.HasPrefix(key, fmt.Sprint(pid)) {
			delete(a.mySqlStmts, key)
		}
	}
	a.mySqlStmtsMu.Unlock()
}

func (a *Aggregator) signalTlsAttachment(pid uint32) {
	a.tlsAttachSignalChan <- pid
}

func (a *Aggregator) processTcpConnect(ctx context.Context, d *tcp_state.TcpConnectEvent) {
	go a.signalTlsAttachment(d.Pid)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {

		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		var sockMap *SocketMap
		var ok bool

		sockMap = a.clusterInfo.SocketMaps[d.Pid]
		if sockMap == nil {
			// signal socket map creation and requeue event
			log.Logger.Warn().Ctx(ctx).
				Uint32("pid", d.Pid).Str("func", "processTcpConnect").Str("event", "ESTABLISHED").Msg("socket map not initialized")

			go a.clusterInfo.SignalSocketMapCreation(d.Pid)
			a.ebpfTcpChan <- d
			return
		}

		var skLine *SocketLine

		sockMap.mu.RLock()
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock()
		if !ok {
			go sockMap.SignalSocketLine(ctx, d.Fd) // signal for creation
			// requeue connect event
			a.ebpfTcpChan <- d
			return
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
	} else if d.Type_ == tcp_state.EVENT_TCP_CLOSED {
		var sockMap *SocketMap
		var ok bool

		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		sockMap = a.clusterInfo.SocketMaps[d.Pid]
		if sockMap == nil {
			// signal socket map creation and requeue event
			log.Logger.Warn().Ctx(ctx).
				Uint32("pid", d.Pid).Str("func", "processTcpConnect").Str("event", "ESTABLISHED").Msg("socket map not initialized")

			go a.clusterInfo.SignalSocketMapCreation(d.Pid)
			a.ebpfTcpChan <- d
			return
		}

		var skLine *SocketLine
		sockMap.mu.RLock()
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock()
		if !ok {
			return
		}

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

		addrPair := extractAddressPair(d)

		req.Latency = d.WriteTimeNs - req.Latency
		req.StartTime = int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6) // nano to milli
		req.Completed = true
		req.FromIP = addrPair.Saddr
		req.ToIP = addrPair.Daddr
		req.Tls = d.Tls
		req.FromPort = addrPair.Sport
		req.ToPort = addrPair.Dport
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
		err := a.setFromToV2(addrPair, d, req, req.ToUID)
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

func (a *Aggregator) setFromToV2(addrPair *AddressPair, d *l7_req.L7Event, event datastore.DirectionalEvent, hostHeader string) error {
	// find pod info
	podUid, ok := a.getPodWithIP(addrPair.Saddr)
	if !ok {
		return fmt.Errorf("error finding pod with sockets saddr")
	}

	event.SetFromUID(string(podUid))
	event.SetFromType(POD)
	event.SetFromPort(addrPair.Sport)
	event.SetToPort(addrPair.Dport)

	// find service info
	svcUid, ok := a.getSvcWithIP(addrPair.Daddr)
	if ok {
		event.SetToUID(string(svcUid))
		event.SetToType(SVC)
	} else {
		podUid, ok := a.getPodWithIP(addrPair.Daddr)

		if ok {
			event.SetToUID(string(podUid))
			event.SetToType(POD)
		} else {
			// 3rd party url
			if hostHeader != "" {
				event.SetToUID(hostHeader)
				event.SetToType(OUTBOUND)
			} else {
				remoteDnsHost, err := getHostnameFromIP(addrPair.Daddr)
				if err == nil {
					// dns lookup successful
					event.SetToUID(remoteDnsHost)
					event.SetToType(OUTBOUND)
				} else {
					event.SetToUID(addrPair.Daddr)
					event.SetToType(OUTBOUND)
				}
			}
		}
	}

	return nil
}

func (a *Aggregator) setFromTo(skInfo *SockInfo, d *l7_req.L7Event, event datastore.DirectionalEvent, hostHeader string) error {
	// find pod info
	podUid, ok := a.getPodWithIP(skInfo.Saddr)
	if !ok {
		return fmt.Errorf("error finding pod with sockets saddr")
	}

	event.SetFromUID(string(podUid))
	event.SetFromType(POD)
	event.SetFromPort(skInfo.Sport)
	event.SetToPort(skInfo.Dport)

	// find service info
	svcUid, ok := a.getSvcWithIP(skInfo.Daddr)
	if ok {
		event.SetToUID(string(svcUid))
		event.SetToType(SVC)
	} else {
		podUid, ok := a.getPodWithIP(skInfo.Daddr)

		if ok {
			event.SetToUID(string(podUid))
			event.SetToType(POD)
		} else {
			// 3rd party url
			if hostHeader != "" {
				event.SetToUID(hostHeader)
				event.SetToType(OUTBOUND)
			} else {
				remoteDnsHost, err := getHostnameFromIP(skInfo.Daddr)
				if err == nil {
					// dns lookup successful
					event.SetToUID(remoteDnsHost)
					event.SetToType(OUTBOUND)
				} else {
					event.SetToUID(skInfo.Daddr)
					event.SetToType(OUTBOUND)
				}
			}
		}
	}

	return nil
}

func (a *Aggregator) getConnKey(pid uint32, fd uint64) string {
	return fmt.Sprintf("%d-%d", pid, fd)
}

type KafkaMessage struct {
	TopicName string
	Partition int32
	Key       string
	Value     string
	Type      string // PUBLISH or CONSUME
}

func (a *Aggregator) decodeKafkaPayload(d *l7_req.L7Event) ([]*KafkaMessage, error) {
	// apiVersion is written in request header
	// response header only has correlation_id
	// so while returning a response message from kafka, we need to send the api version to userspace
	// in order to parse the response message.
	// d.KafkaApiVersion is set in kafka request event

	// r := bytes.NewReader(d.Payload[:d.PayloadSize])

	// var apiVersion int16    // only in request
	// var clientID string     // only in request
	// var correlationID int32 // both in request and response
	// var message protocol.Message
	// var err error

	defer func() {
		if r := recover(); r != nil {
			log.Logger.Debug().Any("r", r).
				Msg("recovered from kafka event,probably slice out of bounds") // since we read 1024 bytes at most from ebpf, slice out of bounds can occur
		}
	}()

	result := make([]*KafkaMessage, 0)

	if d.Method == l7_req.KAFKA_PRODUCE_REQUEST {
		saramaReq, _, err := kafka.DecodeRequest(bytes.NewReader(d.Payload[:d.PayloadSize]))
		if err != nil {
			// non-kafka messages sometimes classifed as kafka messages on kernel side
			return nil, fmt.Errorf("kafka decode request failure: %w", err)
		} else {
			rs := saramaReq.Body.(*kafka.ProduceRequest).Records
			for topicName, r := range rs {
				for partition, record := range r {
					records := record.RecordBatch.Records
					for _, msg := range records {
						result = append(result, &KafkaMessage{
							TopicName: topicName,
							Partition: partition,
							Key:       string(msg.Key),
							Value:     string(msg.Value),
							Type:      "PUBLISH",
						})
					}
				}
			}
		}
	} else if d.Method == l7_req.KAFKA_FETCH_RESPONSE {
		payload := d.Payload[:d.PayloadSize]
		// decode response header first
		decodedHeader := &kafka.ResponseHeader{}
		off, err := kafka.VersionedDecode(payload, decodedHeader, kafka.ResponseHeaderVersion(1, d.KafkaApiVersion))
		if err != nil {
			return nil, fmt.Errorf("kafka decode response header failure: %w", err)
		}

		// skip header
		payload = payload[off:]
		fetchApiVersion := d.KafkaApiVersion

		res := &kafka.FetchResponse{}
		_, err = kafka.VersionedDecode(payload, res, fetchApiVersion)
		if err != nil {
			return nil, fmt.Errorf("kafka decode fetch response failure: %w", err)
		} else {
			for topic, mapfrb := range res.Blocks {
				for partition, frb := range mapfrb {
					log.Logger.Warn().Int32("partition", partition).Msg("sarama kafka fetch data- partition")
					recordSet := frb.RecordsSet
					for _, record := range recordSet {
						// record.MsgSet --> legacy records
						// record.RecordBatch --> default records
						for _, r := range record.RecordBatch.Records {
							result = append(result, &KafkaMessage{
								TopicName: topic,
								Partition: partition,
								Key:       string(r.Key),
								Value:     string(r.Value),
								Type:      "CONSUME",
							})
						}
					}
				}
			}
		}

	}

	return result, nil
}

func (a *Aggregator) processHttp2Event(d *l7_req.L7Event) {
	// http2 events come as frames
	// we need to aggregate frames to get the whole request
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

func (a *Aggregator) processKafkaEvent(ctx context.Context, d *l7_req.L7Event) {
	kafkaMessages, err := a.decodeKafkaPayload(d)
	if err != nil || len(kafkaMessages) == 0 {
		return
	}

	addrPair := extractAddressPair(d)

	for _, msg := range kafkaMessages {
		event := &datastore.KafkaEvent{
			StartTime: int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
			Latency:   d.Duration,
			FromIP:    addrPair.Saddr,
			FromType:  "",
			FromUID:   "",
			FromPort:  addrPair.Sport,
			ToIP:      addrPair.Daddr,
			ToType:    "",
			ToUID:     "",
			ToPort:    addrPair.Dport,
			Tls:       d.Tls,
			Topic:     msg.TopicName,
			Partition: uint32(msg.Partition),
			Key:       msg.Key,
			Value:     msg.Value,
			Type:      msg.Type,
			// dist tracing disabled by default temporarily
			// Tid:       d.Tid,
			// Seq:       d.Seq,
		}

		err := a.setFromToV2(addrPair, d, event, "")
		if err != nil {
			return
		}

		log.Logger.Debug().Ctx(ctx).Any("kafkaEvent", event).Msg("persist kafka event")
		err = a.ds.PersistKafkaEvent(event)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error persisting kafka event")
		}
	}
	return

}

func (a *Aggregator) processAmqpEvent(ctx context.Context, d *l7_req.L7Event) {
	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       "",
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err := a.setFromToV2(addrPair, d, reqDto, "")
	if err != nil {
		return
	}

	// In AMQP-DELIVER or REDIS-PUSHED_EVENT event, we are capturing from read syscall,
	// exchange sockets
	// In Alaz context, From is always the one that makes the write
	// and To is the one that makes the read
	if d.Method == l7_req.DELIVER {
		reqDto.ReverseDirection()
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}
}

func (a *Aggregator) processRedisEvent(ctx context.Context, d *l7_req.L7Event) {
	query := string(d.Payload[0:d.PayloadSize])

	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       query,
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err := a.setFromToV2(addrPair, d, reqDto, "")
	if err != nil {
		return
	}

	// REDIS-PUSHED_EVENT event, we are capturing from read syscall,
	// exchange sockets
	// In Alaz context, From is always the one that makes the write
	// and To is the one that makes the read
	if d.Method == l7_req.REDIS_PUSHED_EVENT {
		reqDto.ReverseDirection()
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Ctx(ctx).
			Err(err).Msg("error persisting request")
	}
}

func (a *Aggregator) AdvertiseDebugData() {
	http.HandleFunc("/pid-sock-map",
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

			sockMap := a.clusterInfo.SocketMaps[pid]
			if sockMap == nil {
				http.Error(w, "Pid not found", http.StatusNotFound)
				return
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_ = json.NewEncoder(w).Encode(sockMap)
				return
			}
		},
	)

	// http.HandleFunc("/process-latency",
	// 	func(w http.ResponseWriter, r *http.Request) {
	// 		latency := a.totalLatency.Load()
	// 		count := a.latencyCount.Load()
	// 		if count == 0 {
	// 			http.Error(w, "No data available", http.StatusNotFound)
	// 			return
	// 		}
	// 		avgLatency := float64(latency) / float64(count)
	// 		w.Header().Set("Content-Type", "application/json")
	// 		w.WriteHeader(http.StatusOK)
	// 		_ = json.NewEncoder(w).Encode(map[string]float64{
	// 			"average_latency_in_ns": avgLatency,
	// 		})
	// 		return
	// 	})
}

func (a *Aggregator) processHttpEvent(ctx context.Context, d *l7_req.L7Event) {
	var reqHostHeader string
	var path string
	// parse http payload, extract path, query params, headers
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP {
		_, path, _, reqHostHeader = parseHttpPayload(string(d.Payload[0:d.PayloadSize]))
	}

	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       path,
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err := a.setFromToV2(addrPair, d, reqDto, reqHostHeader)
	if err != nil {
		return
	}

	if d.Protocol == l7_req.L7_PROTOCOL_HTTP && d.Tls {
		reqDto.Protocol = "HTTPS"
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}

}

func (a *Aggregator) processMongoEvent(ctx context.Context, d *l7_req.L7Event) {
	query, err := a.parseMongoEvent(d)
	if err != nil {
		log.Logger.Error().AnErr("err", err)
		return
	}
	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       query,
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err = a.setFromToV2(addrPair, d, reqDto, "")
	if err != nil {
		return
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}
}

func (a *Aggregator) processMySQLEvent(ctx context.Context, d *l7_req.L7Event) {
	query, err := a.parseMySQLCommand(d)
	if err != nil {
		log.Logger.Error().AnErr("err", err)
		return
	}
	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       query,
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err = a.setFromToV2(addrPair, d, reqDto, "")
	if err != nil {
		return
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}
}

func (a *Aggregator) processPostgresEvent(ctx context.Context, d *l7_req.L7Event) {
	// parse sql command from payload
	// path = sql command
	// method = sql message type

	query, err := a.parsePostgresCommand(d)
	if err != nil {
		log.Logger.Error().AnErr("err", err)
		return
	}

	addrPair := extractAddressPair(d)

	reqDto := &datastore.Request{
		StartTime:  int64(convertKernelTimeToUserspaceTime(d.WriteTimeNs) / 1e6),
		Latency:    d.Duration,
		FromIP:     addrPair.Saddr,
		ToIP:       addrPair.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
		Path:       query,
		// dist tracing disabled by default temporarily
		// Tid:        d.Tid,
		// Seq:        d.Seq,
	}

	err = a.setFromToV2(addrPair, d, reqDto, "")
	if err != nil {
		return
	}

	err = a.ds.PersistRequest(reqDto)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error persisting request")
	}
}

func (a *Aggregator) processL7(ctx context.Context, d *l7_req.L7Event) {
	switch d.Protocol {
	case l7_req.L7_PROTOCOL_HTTP2:
		a.processHttp2Event(d)
	case l7_req.L7_PROTOCOL_POSTGRES:
		a.processPostgresEvent(ctx, d)
	case l7_req.L7_PROTOCOL_HTTP:
		a.processHttpEvent(ctx, d)
	case l7_req.L7_PROTOCOL_REDIS:
		a.processRedisEvent(ctx, d)
	case l7_req.L7_PROTOCOL_AMQP:
		a.processAmqpEvent(ctx, d)
	case l7_req.L7_PROTOCOL_KAFKA:
		a.processKafkaEvent(ctx, d)
	case l7_req.L7_PROTOCOL_MYSQL:
		a.processMySQLEvent(ctx, d)
	case l7_req.L7_PROTOCOL_MONGO:
		a.processMongoEvent(ctx, d)
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

func (a *Aggregator) findRelatedSocket(ctx context.Context, d *l7_req.L7Event) (*SockInfo, error) {
	sockMap := a.clusterInfo.SocketMaps[d.Pid]
	// acquire sockMap lock
	if sockMap == nil {
		go a.clusterInfo.SignalSocketMapCreation(d.Pid)
		return nil, fmt.Errorf("socket map not initialized for pid=%d, fd=%d", d.Pid, d.Fd)
	}

	sockMap.mu.RLock()
	skLine, ok := sockMap.M[d.Fd]
	sockMap.mu.RUnlock()
	if !ok {
		// start new socket line, find already established connections
		go sockMap.SignalSocketLine(ctx, d.Fd)
		return nil, fmt.Errorf("socket line not initialized for fd=%d, pid=%d", d.Fd, d.Pid)
	}

	skInfo, err := skLine.GetValue(d.WriteTimeNs)
	if err != nil {
		return nil, fmt.Errorf("could not find remote peer from given timestamp, err=%v, fd=%d, pid=%d", err, d.Fd, d.Pid)
	}
	return skInfo, nil
}

func (a *Aggregator) parseMySQLCommand(d *l7_req.L7Event) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	// 3 bytes len, 1 byte package number, 1 byte command type
	if len(r) < 5 {
		return "", fmt.Errorf("too short for a sql query")
	}
	r = r[5:]
	sqlCommand = string(r)
	if d.Method == l7_req.MYSQL_TEXT_QUERY {
		if !containsSQLKeywords(sqlCommand) {
			return "", fmt.Errorf("no sql command found")
		}
	} else if d.Method == l7_req.MYSQL_PREPARE_STMT {
		a.mySqlStmtsMu.Lock()
		a.mySqlStmts[fmt.Sprintf("%d-%d-%d", d.Pid, d.Fd, d.MySqlPrepStmtId)] = string(r)
		a.mySqlStmtsMu.Unlock()
	} else if d.Method == l7_req.MYSQL_EXEC_STMT {
		a.mySqlStmtsMu.RLock()
		// extract statementId from payload
		stmtId := binary.LittleEndian.Uint32(r)
		query, ok := a.mySqlStmts[fmt.Sprintf("%d-%d-%d", d.Pid, d.Fd, stmtId)]
		a.mySqlStmtsMu.RUnlock()
		if !ok || query == "" { // we don't have the query for the prepared statement
			// Execute (name of prepared statement) [(parameter)]
			return fmt.Sprintf("EXECUTE %d *values*", stmtId), nil
		}
		sqlCommand = query
	} else if d.Method == l7_req.MYSQL_STMT_CLOSE { // deallocated stmt
		a.mySqlStmtsMu.Lock()
		// extract statementId from payload
		stmtId := binary.LittleEndian.Uint32(r)
		stmtKey := fmt.Sprintf("%d-%d-%d", d.Pid, d.Fd, stmtId)
		_, ok := a.mySqlStmts[stmtKey]
		if ok {
			delete(a.mySqlStmts, stmtKey)
		}
		a.mySqlStmtsMu.Unlock()
		return fmt.Sprintf("CLOSE STMT %d ", stmtId), nil
	}
	return sqlCommand, nil
}

func (a *Aggregator) parsePostgresCommand(d *l7_req.L7Event) (string, error) {
	r := d.Payload[:d.PayloadSize]
	var sqlCommand string
	if d.Method == l7_req.SIMPLE_QUERY {
		// Q, 4 bytes of length, sql command

		if len(r) < 5 {
			return "", fmt.Errorf("too short for a sql query")
		}

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

func (a *Aggregator) parseMongoEvent(d *l7_req.L7Event) (string, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Logger.Debug().Any("r", r).
				Msg("recovered from mongo event,probably slice out of bounds")
		}
	}()

	payload := d.Payload[:d.PayloadSize]

	// cut mongo header, 4 bytes MessageLength, 4 bytes RequestID, 4 bytes ResponseTo, 4 bytes Opcode, 4 bytes MessageFlags
	payload = payload[20:]

	kind := payload[0]
	payload = payload[1:] // cut kind
	if kind == 0 {        // body
		docLenBytes := payload[:4] // document length
		docLen := binary.LittleEndian.Uint32(docLenBytes)
		payload = payload[4:docLen] // cut docLen
		// parse Element
		type_ := payload[0] // 2 means string
		if type_ != 2 {
			return "", fmt.Errorf("document element not a string")
		}
		payload = payload[1:] // cut type

		// read until NULL
		element := []uint8{}
		for _, p := range payload {
			if p == 0 {
				break
			}
			element = append(element, p)
		}

		// 1 byte NULL, 4 bytes len
		elementLenBytes := payload[len(element)+1 : len(element)+1+4]
		elementLength := binary.LittleEndian.Uint32(elementLenBytes)

		payload = payload[len(element)+5:]        // cut element + null + len
		elementValue := payload[:elementLength-1] // myCollection, last byte is null

		result := fmt.Sprintf("%s %s", string(element), string(elementValue))
		log.Logger.Debug().Str("result", result).Msg("mongo-elem-result")
		return result, nil
	}

	return "", fmt.Errorf("could not parse mongo event")
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
	ticker := time.NewTicker(120 * time.Second)
	skLineCh := make(chan *SocketLine, 1000)

	sendAliveConnections, _ := strconv.ParseBool(os.Getenv("SEND_ALIVE_TCP_CONNECTIONS"))
	go func() {
		// spawn N goroutines to clear socket map
		for i := 0; i < 10; i++ {
			go func() {
				for skLine := range skLineCh {
					// send open connections to datastore
					if sendAliveConnections {
						a.sendOpenConnection(skLine)
					}
					// clear socket history
					skLine.DeleteUnused()
				}
			}()
		}
	}()

	for range ticker.C {
		for _, sockMap := range a.clusterInfo.SocketMaps {
			if sockMap == nil {
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

func convertKernelTimeToUserspaceTime(writeTime uint64) uint64 {
	// get first timestamp from kernel and corresponding userspace time
	return l7_req.FirstUserspaceTime - (l7_req.FirstKernelTime - writeTime)
}

func convertUserTimeToKernelTime(now uint64) uint64 {
	return l7_req.FirstKernelTime - (l7_req.FirstUserspaceTime - now)
}

// IntToIPv4 converts IP address of version 4 from integer to net.IP
// representation.
func IntToIPv4(ipaddr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)

	// Proceed conversion
	binary.BigEndian.PutUint32(ip, ipaddr)

	return ip
}

func extractAddressPair(d *l7_req.L7Event) *AddressPair {
	return &AddressPair{
		Saddr: IntToIPv4(d.Saddr).String(),
		Sport: d.Sport,
		Daddr: IntToIPv4(d.Daddr).String(),
		Dport: d.Dport,
	}
}
