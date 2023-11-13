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
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/ebpf/l7_req"
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
	k8sChan  <-chan interface{}
	ebpfChan <-chan interface{}

	ec *ebpf.EbpfCollector

	// store the service map
	clusterInfo *ClusterInfo

	// send data to datastore
	ds datastore.DataStore

	// http2 ch
	h2ChMu sync.RWMutex
	h2Ch   map[string]chan *l7_req.L7Event // pid-fd -> ch
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

	h2parser *http2Parser
}

type http2Parser struct {
	// Framer is the HTTP/2 framer to use.
	framer *http2.Framer
	// framer.ReadFrame() returns a frame, which is a struct

	// http2 request and response dynamic tables are separate
	// 2 decoders are needed
	// https://httpwg.org/specs/rfc7541.html#encoding.context
	clientHpackDecoder *hpack.Decoder
	serverHpackDecoder *hpack.Decoder
}

// type SocketMap
type SocketMap struct {
	mu sync.RWMutex
	M  map[uint64]*SocketLine `json:"fdToSockLine"` // fd -> SockLine
}

type ClusterInfo struct {
	mu                    sync.RWMutex
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	// Pid -> SocketMap
	// pid -> fd -> {saddr, sport, daddr, dport}
	PidToSocketMap map[uint32]*SocketMap `json:"pidToSocketMap"`
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
	// when retryLimit is increased, we are blocking the events that we wait it to be processed more
	retryInterval = 400 * time.Millisecond
	retryLimit    = 5
	// 400 + 800 + 1600 + 3200 + 6400 = 12400 ms

	defaultExpiration = 5 * time.Minute
	purgeTime         = 10 * time.Minute
)

var usePgDs bool = false
var useBackendDs bool = true // default to true
var reverseDnsCache *cache.Cache

func init() {
	reverseDnsCache = cache.New(defaultExpiration, purgeTime)
}

func NewAggregator(parentCtx context.Context, k8sChan <-chan interface{}, ec *ebpf.EbpfCollector, ds datastore.DataStore) *Aggregator {
	ctx, _ := context.WithCancel(parentCtx)
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		PidToSocketMap:        make(map[uint32]*SocketMap, 0),
	}

	go clearSocketLines(ctx, clusterInfo.PidToSocketMap)

	return &Aggregator{
		ctx:         ctx,
		k8sChan:     k8sChan,
		ebpfChan:    ec.EbpfEvents(),
		ec:          ec,
		clusterInfo: clusterInfo,
		ds:          ds,
		h2Ch:        make(map[string]chan *l7_req.L7Event),
	}
}

func (a *Aggregator) Run() {
	go a.processk8s()

	numWorker := 10
	for i := 0; i < numWorker; i++ {
		go a.processEbpf(a.ctx)
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

func (a *Aggregator) processEbpf(ctx context.Context) {
	stop := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stop)
	}()

	for data := range a.ebpfChan {
		select {
		case <-stop:
			log.Logger.Info().Msg("processEbpf exiting...")
			return
		default:
			bpfEvent, ok := data.(ebpf.BpfEvent)
			if !ok {
				log.Logger.Error().Interface("ebpfData", data).Msg("error casting ebpf event")
				continue
			}
			switch bpfEvent.Type() {
			case tcp_state.TCP_CONNECT_EVENT:
				d := data.(tcp_state.TcpConnectEvent) // copy data's value
				tcpConnectEvent := tcp_state.TcpConnectEvent{
					Fd:        d.Fd,
					Timestamp: d.Timestamp,
					Type_:     d.Type_,
					Pid:       d.Pid,
					SPort:     d.SPort,
					DPort:     d.DPort,
					SAddr:     d.SAddr,
					DAddr:     d.DAddr,
				}
				go a.processTcpConnect(tcpConnectEvent)
			case l7_req.L7_EVENT:
				d := data.(l7_req.L7Event) // copy data's value

				// copy payload slice
				payload := [1024]uint8{}
				copy(payload[:], d.Payload[:])

				l7Event := l7_req.L7Event{
					Fd:                  d.Fd,
					Pid:                 d.Pid,
					Status:              d.Status,
					Duration:            d.Duration,
					Protocol:            d.Protocol,
					Tls:                 d.Tls,
					Method:              d.Method,
					Payload:             payload,
					PayloadSize:         d.PayloadSize,
					PayloadReadComplete: d.PayloadReadComplete,
					Failed:              d.Failed,
					WriteTimeNs:         d.WriteTimeNs,
				}
				go a.processL7(ctx, l7Event)
			}
		}
	}
}

func (a *Aggregator) processTcpConnect(data interface{}) {
	d := data.(tcp_state.TcpConnectEvent)
	go a.ec.ListenForEncryptedReqs(d.Pid)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {
		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		var sockMap *SocketMap
		var ok bool

		a.clusterInfo.mu.RLock() // lock for reading
		sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]
		a.clusterInfo.mu.RUnlock() // unlock for reading
		if !ok {
			sockMap = &SocketMap{
				M:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}
			a.clusterInfo.mu.Lock() // lock for writing
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
			a.clusterInfo.mu.Unlock() // unlock for writing
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock() // unlock for reading

		if !ok {
			skLine = NewSocketLine(d.Pid, d.Fd)
			sockMap.mu.Lock() // lock for writing
			sockMap.M[d.Fd] = skLine
			sockMap.mu.Unlock() // unlock for writing
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

		a.clusterInfo.mu.RLock() // lock for reading
		sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]
		a.clusterInfo.mu.RUnlock() // unlock for reading

		if !ok {
			sockMap = &SocketMap{
				M:  make(map[uint64]*SocketLine),
				mu: sync.RWMutex{},
			}

			a.clusterInfo.mu.Lock() // lock for writing
			a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
			a.clusterInfo.mu.Unlock() // unlock for writing
			return
		}

		var skLine *SocketLine

		sockMap.mu.RLock() // lock for reading
		skLine, ok = sockMap.M[d.Fd]
		sockMap.mu.RUnlock() // unlock for reading

		if !ok {
			return
		}

		// If connection is established before, add the close event
		skLine.AddValue(
			d.Timestamp, // get connection close timestamp from ebpf
			nil,         // closed
		)

		// close h2 channel on connection close if exists
		// a.h2ChMu.Lock()
		// key := fmt.Sprintf("%d-%d", d.Pid, d.Fd)
		// if _, ok := a.h2Ch[key]; ok {
		// 	// close(a.h2Ch[key])
		// 	delete(a.h2Ch, key)
		// }
		// a.h2ChMu.Unlock()

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
}

// called once per socket
// TODO: must close on process close
func (a *Aggregator) processHttp2Frames(ch chan *l7_req.L7Event) {
	mu := sync.RWMutex{}
	h2Parser := &http2Parser{
		clientHpackDecoder: hpack.NewDecoder(4096, nil),
		serverHpackDecoder: hpack.NewDecoder(4096, nil),
	}

	// streamId -> frame
	frames := make(map[uint32]*FrameArrival)

	t := time.NewTicker(1 * time.Second)
	// http2 frames order can be in any order
	// if server data frame comes first, we need to wait for the server headers frame
	// before sending the request to persist
	go func() {
		for range t.C {
			mu.Lock()
			for streamId, st := range frames {
				if st.ClientHeadersFrameArrived && st.ServerHeadersFrameArrived && st.ServerDataFrameArrived {
					// request completed, server sent response
					// Process server data frame, send L7 event to persist
					go func(d *l7_req.L7Event, req *datastore.Request) {
						skInfo := a.findRelatedSocket(a.ctx, d)
						if skInfo == nil {
							return
						}

						req.StartTime = time.Now().UnixMilli()
						req.Latency = d.WriteTimeNs - req.Latency
						req.Completed = true
						req.FromIP = skInfo.Saddr
						req.ToIP = skInfo.Daddr
						req.Protocol = "HTTP2"
						req.Tls = d.Tls
						req.FromPort = skInfo.Sport
						req.ToPort = skInfo.Dport
						req.FailReason = ""

						// toUID is set to :authority header in client frame
						err := a.setFromTo(skInfo, d, req, req.ToUID)
						if err != nil {
							// log.Logger.Error().Err(err).Msg("error setting from/to")
							return
						}

						// TODO: set protocol
						// if d.Tls {
						// 	req.Protocol = "HTTPS"
						// }

						log.Logger.Debug().
							Uint32("streamId", streamId).
							Str("path", req.Path).
							Str("method", req.Method).
							Uint32("statusCode", req.StatusCode).
							Str("fromUID", req.FromUID).
							Str("toUID", req.ToUID).
							Str("fromIP", req.FromIP).
							Uint16("fromPort", req.FromPort).
							Str("toIP", req.ToIP).
							Uint16("toPort", req.ToPort).
							Str("fromType", req.FromType).
							Str("toType", req.ToType).
							Str("protocol", req.Protocol).
							Bool("tls", req.Tls).
							Bool("completed", req.Completed).
							Uint64("latency", req.Latency).
							Msg("http2 request persisting")

						a.ds.PersistRequest(req)
					}(st.event, st.req)
					delete(frames, streamId)
				}
			}
			mu.Unlock()
		}
	}()

	for d := range ch {
		framer := http2.NewFramer(nil, bytes.NewReader(d.Payload[0:d.PayloadSize]))

		// parse frame
		// https://httpwg.org/specs/rfc7540.html#rfc.section.4.1
		if d.Method == l7_req.CLIENT_FRAME {
			loop := true
			for loop {
				// can be multiple frames in the payload
				// check golang.org/x/net/http2/frame.go:1587 for handling of CONTINUATION frames
				f, err := framer.ReadFrame()
				if err != nil {
					break
				}

				switch f := f.(type) {
				case *http2.HeadersFrame:
					streamId := f.Header().StreamID
					mu.Lock()
					if _, ok := frames[streamId]; !ok {
						frames[streamId] = &FrameArrival{
							ClientHeadersFrameArrived: true,
							req:                       &datastore.Request{},
						}
					}

					fa := frames[streamId]
					mu.Unlock()
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
								log.Logger.Info().Str("content-type", hf.Value).Msg("content-type")
							case ":content-type":
								log.Logger.Info().Str("content-type", hf.Value).Msg("content-type")
							}

						}
					}
					h2Parser.clientHpackDecoder.SetEmitFunc(reqHeaderSet(fa.req))
					h2Parser.clientHpackDecoder.Write(f.HeaderBlockFragment())

					if f.HeadersEnded() {
						loop = false
					}
				}
			}
		} else if d.Method == l7_req.SERVER_FRAME {
			loop := true
			for loop {
				// can be multiple frames in the payload
				f, err := framer.ReadFrame()
				if err != nil {
					break
				}

				switch f := f.(type) {
				case *http2.HeadersFrame:
					streamId := f.Header().StreamID
					mu.Lock()
					if _, ok := frames[streamId]; !ok {
						frames[streamId] = &FrameArrival{
							ServerHeadersFrameArrived: true,
							req:                       &datastore.Request{},
						}
					}
					fa := frames[streamId]
					mu.Unlock()
					fa.ServerHeadersFrameArrived = true
					// Process server headers frame
					respHeaderSet := func(req *datastore.Request) func(hf hpack.HeaderField) {
						return func(hf hpack.HeaderField) {
							switch hf.Name {
							case ":status":
								s, _ := strconv.Atoi(hf.Value)
								req.StatusCode = uint32(s)
							}
						}
					}

					h2Parser.serverHpackDecoder.SetEmitFunc(respHeaderSet(fa.req))
					h2Parser.serverHpackDecoder.Write(f.HeaderBlockFragment())

				case *http2.DataFrame:
					streamId := f.Header().StreamID
					mu.Lock()
					if _, ok := frames[streamId]; !ok {
						frames[streamId] = &FrameArrival{
							ServerDataFrameArrived: true,
							req:                    &datastore.Request{},
						}
					}
					fa := frames[streamId]
					mu.Unlock()
					fa.ServerDataFrameArrived = true
					fa.event = d

					loop = false // only process the first data frame for now
				}
			}
		} else {
			log.Logger.Error().Msg("unknown http2 frame type")
			continue
		}
	}
}

func (a *Aggregator) setFromTo(skInfo *SockInfo, d *l7_req.L7Event, reqDto *datastore.Request, hostHeader string) error {
	// find pod info
	a.clusterInfo.mu.RLock() // lock for reading
	podUid, ok := a.clusterInfo.PodIPToPodUid[skInfo.Saddr]
	a.clusterInfo.mu.RUnlock() // unlock for reading
	if !ok {
		return fmt.Errorf("error finding pod with sockets saddr")
	}

	reqDto.FromUID = string(podUid)
	reqDto.FromType = "pod"
	reqDto.FromPort = skInfo.Sport
	reqDto.ToPort = skInfo.Dport

	// find service info
	a.clusterInfo.mu.RLock() // lock for reading
	svcUid, ok := a.clusterInfo.ServiceIPToServiceUid[skInfo.Daddr]
	a.clusterInfo.mu.RUnlock() // unlock for reading

	if ok {
		reqDto.ToUID = string(svcUid)
		reqDto.ToType = "service"
	} else {
		a.clusterInfo.mu.RLock() // lock for reading
		podUid, ok := a.clusterInfo.PodIPToPodUid[skInfo.Daddr]
		a.clusterInfo.mu.RUnlock() // unlock for reading

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
					log.Logger.Warn().Err(err).Str("Daddr", skInfo.Daddr).Msg("error getting hostname from ip")
				}
			}
		}
	}

	log.Logger.Info().Str("reqDto.ToType", reqDto.ToType).Str("reqDto.ToUID", reqDto.ToUID).
		Str("skInfo.Daddr", skInfo.Daddr).Str("skInfo.Saddr", skInfo.Saddr).Msg("setFromTo2")

	return nil
}

func (a *Aggregator) processL7(ctx context.Context, d l7_req.L7Event) {
	// other protocols events come as whole, but http2 events come as frames
	// we need to aggregate frames to get the whole request
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP2 {
		var ch chan *l7_req.L7Event
		a.h2ChMu.Lock()
		key := fmt.Sprintf("%d-%d", d.Pid, d.Fd)
		if _, ok := a.h2Ch[key]; !ok {
			a.h2Ch[key] = make(chan *l7_req.L7Event) // TODO: make this configurable
			ch = a.h2Ch[key]
			go a.processHttp2Frames(ch) // worker per connection, will be called once
		} else {
			ch = a.h2Ch[key]
		}
		a.h2ChMu.Unlock()

		ch <- &d
		return
	}

	skInfo := a.findRelatedSocket(ctx, &d)
	if skInfo == nil {
		return
	}

	// Since we process events concurrently
	// TCP events and L7 events can be processed out of order

	reqDto := datastore.Request{
		StartTime:  time.Now().UnixMilli(),
		Latency:    d.Duration,
		FromIP:     skInfo.Saddr,
		ToIP:       skInfo.Daddr,
		Protocol:   d.Protocol,
		Tls:        d.Tls,
		Completed:  true,
		StatusCode: d.Status,
		FailReason: "",
		Method:     d.Method,
	}

	if d.Protocol == l7_req.L7_PROTOCOL_POSTGRES && d.Method == l7_req.SIMPLE_QUERY {
		// parse sql command from payload
		// path = sql command
		// method = sql message type
		reqDto.Path = parseSqlCommand(d.Payload[0:d.PayloadSize])
	}
	var reqHostHeader string
	// parse http payload, extract path, query params, headers
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP {
		_, reqDto.Path, _, reqHostHeader = parseHttpPayload(string(d.Payload[0:d.PayloadSize]))
	}

	err := a.setFromTo(skInfo, &d, &reqDto, reqHostHeader)
	if err != nil {
		return
	}

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

	go func() {
		err := a.ds.PersistRequest(&reqDto)
		if err != nil {
			log.Logger.Error().Err(err).Msg("error persisting request")
		}
	}()
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

func (a *Aggregator) fetchSkLine(sockMap *SocketMap, pid uint32, fd uint64) *SocketLine {
	sockMap.mu.RLock() // lock for reading
	skLine, ok := sockMap.M[fd]
	sockMap.mu.RUnlock() // unlock for reading

	if !ok {
		log.Logger.Debug().Uint32("pid", pid).Uint64("fd", fd).Msg("error finding skLine, go look for it")
		// start new socket line, find already established connections
		skLine = NewSocketLine(pid, fd)
		skLine.GetAlreadyExistingSockets() // find already established connections
		sockMap.mu.Lock()                  // lock for writing
		sockMap.M[fd] = skLine
		sockMap.mu.Unlock() // unlock for writing
	}

	return skLine
}

func (a *Aggregator) fetchSkInfo(ctx context.Context, skLine *SocketLine, d *l7_req.L7Event) *SockInfo {
	rc := retryLimit
	rt := retryInterval
	var skInfo *SockInfo
	var err error

	// skInfo, _ = skLine.GetValue(d.WriteTimeNs)

	for {
		skInfo, err = skLine.GetValue(d.WriteTimeNs)
		if err == nil && skInfo != nil {
			break
		}
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

func (a *Aggregator) fetchSocketMap(pid uint32) *SocketMap {
	var sockMap *SocketMap
	var ok bool

	a.clusterInfo.mu.RLock() // lock for reading
	sockMap, ok = a.clusterInfo.PidToSocketMap[pid]
	a.clusterInfo.mu.RUnlock() // unlock for reading
	if !ok {
		// initialize socket map
		sockMap = &SocketMap{
			M:  make(map[uint64]*SocketLine),
			mu: sync.RWMutex{},
		}
		a.clusterInfo.mu.Lock() // lock for writing
		a.clusterInfo.PidToSocketMap[pid] = sockMap
		a.clusterInfo.mu.Unlock() // unlock for writing

		go a.ec.ListenForEncryptedReqs(pid)
	}
	return sockMap
}

func (a *Aggregator) findRelatedSocket(ctx context.Context, d *l7_req.L7Event) *SockInfo {
	sockMap := a.fetchSocketMap(d.Pid)
	skLine := a.fetchSkLine(sockMap, d.Pid, d.Fd)
	skInfo := a.fetchSkInfo(ctx, skLine, d)

	if skInfo == nil {
		return nil
	}

	// TODO: zero IP address check ??

	return skInfo

}
func parseSqlCommand(r []uint8) string {
	log.Logger.Debug().Uints8("request", r).Msg("parsing sql command")

	// Q, 4 bytes of length, sql command

	// skip Q, (simple query)
	r = r[1:]

	// skip 4 bytes of length
	r = r[4:]

	// get sql command
	sqlStatement := string(r)

	return sqlStatement
}

func clearSocketLines(ctx context.Context, pidToSocketMap map[uint32]*SocketMap) {
	ticker := time.NewTicker(1 * time.Minute)
	skLineCh := make(chan *SocketLine, 1000)

	go func() {
		// spawn N goroutines to clear socket map
		for i := 0; i < 10; i++ {
			go func() {
				for skLine := range skLineCh {
					skLine.DeleteUnused()
				}
			}()
		}
	}()

	for range ticker.C {
		for _, socketMap := range pidToSocketMap {
			for _, socketLine := range socketMap.M {
				skLineCh <- socketLine
			}
		}
	}
}
