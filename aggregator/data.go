package aggregator

// aggregate data from different sources
// 1. k8s
// 2. containerd (TODO)
// 3. ebpf
// 4. cgroup (TODO)
// 5. docker (TODO)

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/ebpf"
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/ebpf/tcp_state"
	"github.com/ddosify/alaz/log"

	"github.com/ddosify/alaz/k8s"

	"github.com/patrickmn/go-cache"
	"k8s.io/apimachinery/pkg/types"
)

type Aggregator struct {
	// listen to events from different sources
	k8sChan  <-chan interface{}
	ebpfChan <-chan interface{}

	ec *ebpf.EbpfCollector

	// store the service map
	clusterInfo *ClusterInfo

	// send data to datastore
	ds datastore.DataStore
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

func NewAggregator(k8sChan <-chan interface{}, ec *ebpf.EbpfCollector, ds datastore.DataStore) *Aggregator {
	clusterInfo := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
		PidToSocketMap:        make(map[uint32]*SocketMap, 0),
	}

	return &Aggregator{
		k8sChan:     k8sChan,
		ebpfChan:    ec.EbpfEvents(),
		ec:          ec,
		clusterInfo: clusterInfo,
		ds:          ds,
	}
}

func (a *Aggregator) Run() {
	go a.processk8s()
	go a.processEbpf()
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

func (a *Aggregator) processEbpf() {
	for data := range a.ebpfChan {
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
			payload := [512]uint8{}
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
			go a.processL7(l7Event)
		}
	}
}

func (a *Aggregator) processTcpConnect(data interface{}) {
	d := data.(tcp_state.TcpConnectEvent)
	go a.ec.ListenForTlsReqs(d.Pid)
	if d.Type_ == tcp_state.EVENT_TCP_ESTABLISHED {
		// filter out localhost connections
		if d.SAddr == "127.0.0.1" || d.DAddr == "127.0.0.1" {
			return
		}

		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).
			Str("saddr", d.SAddr).Uint16("sport", d.SPort).
			Str("daddr", d.DAddr).Uint16("dport", d.DPort).
			Msg("TCP_ESTABLISHED event")

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
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).
			Str("saddr", d.SAddr).Uint16("sport", d.SPort).
			Str("daddr", d.DAddr).Uint16("dport", d.DPort).
			Uint64("closeTime", d.Timestamp).
			Msg("TCP_CLOSED event")

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

func (a *Aggregator) processL7(d l7_req.L7Event) {
	var sockMap *SocketMap
	var skLine *SocketLine
	var ok bool

	a.clusterInfo.mu.RLock() // lock for reading
	sockMap, ok = a.clusterInfo.PidToSocketMap[d.Pid]
	a.clusterInfo.mu.RUnlock() // unlock for reading
	if !ok {
		log.Logger.Info().Uint32("pid", d.Pid).Msg("error finding socket map, initializing...")
		// initialize socket map
		sockMap = &SocketMap{
			M:  make(map[uint64]*SocketLine),
			mu: sync.RWMutex{},
		}
		a.clusterInfo.mu.Lock() // lock for writing
		a.clusterInfo.PidToSocketMap[d.Pid] = sockMap
		a.clusterInfo.mu.Unlock() // unlock for writing

		go a.ec.ListenForTlsReqs(d.Pid)
	}

	sockMap.mu.RLock() // lock for reading
	skLine, ok = sockMap.M[d.Fd]
	sockMap.mu.RUnlock() // unlock for reading

	if !ok {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Msg("error finding skLine, go look for it")
		// start new socket line, find already established connections
		skLine = NewSocketLine(d.Pid, d.Fd)
		skLine.GetAlreadyExistingSockets() // find already established connections
		sockMap.mu.Lock()                  // lock for writing
		sockMap.M[d.Fd] = skLine
		sockMap.mu.Unlock() // unlock for writing
	}

	// In case of late request, we don't have socket info
	// ESTABLISHED
	// CLOSED
	// Request (late)

	// Request (early)
	// ESTABLISHED
	// CLOSED

	// Ideal case
	// ESTABLISHED
	// Request
	// Request ...
	// CLOSED

	// Since we process events concurrently,
	// CLOSED event can be processed before ESTABLISHED event (goroutine scheduling)

	rc := retryLimit
	rt := retryInterval
	var skInfo *SockInfo
	var err error

	for {
		skInfo, err = skLine.GetValue(d.WriteTimeNs)
		if err == nil && skInfo != nil {
			break
		}
		rc--
		time.Sleep(rt)
		rt *= 2 // exponential backoff
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("retrying getting socket info from skLine")

		if rc == 0 {
			break
		}
	}

	if rc < retryLimit && skInfo != nil {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Msg("found socket info with retry")
	}

	if err != nil || skInfo == nil {
		log.Logger.Debug().Uint32("pid", d.Pid).Uint64("fd", d.Fd).Uint64("writeTimeNs", d.WriteTimeNs).
			Str("method", d.Method).Uint32("status", d.Status).Str("protocol", d.Protocol).Str("payload", string(d.Payload[0:d.PayloadSize])).
			Msg("could not match socket, discarding request")
		return
	}

	// assuming successful request
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

	var reqHostHeader string
	// parse http payload, extract path, query params, headers
	if d.Protocol == l7_req.L7_PROTOCOL_HTTP {
		_, reqDto.Path, _, reqHostHeader = parseHttpPayload(string(d.Payload[0:d.PayloadSize]))
		log.Logger.Debug().Str("path", reqDto.Path).Msg("path extracted from http payload")
	}

	if d.Protocol == l7_req.L7_PROTOCOL_POSTGRES && d.Method == l7_req.SIMPLE_QUERY {
		// parse sql command from payload
		// path = sql command
		// method = sql message type
		reqDto.Path = parseSqlCommand(d.Payload[0:d.PayloadSize])
		log.Logger.Debug().Str("path", reqDto.Path).Msg("path extracted from postgres payload")
	}

	// find pod info
	a.clusterInfo.mu.RLock() // lock for reading
	podUid, ok := a.clusterInfo.PodIPToPodUid[skInfo.Saddr]
	a.clusterInfo.mu.RUnlock() // unlock for reading
	if !ok {
		log.Logger.Debug().Str("Saddr", skInfo.Saddr).
			Int("pid", int(d.Pid)).
			Uint64("fd", d.Fd).
			Msg("error finding pod with sockets saddr")
		return
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
			if reqHostHeader != "" {
				reqDto.ToUID = reqHostHeader
				reqDto.ToType = "outbound"
			} else {
				remoteDnsHost, err := getHostnameFromIP(skInfo.Daddr)
				if err == nil {
					// dns lookup successful
					reqDto.ToUID = remoteDnsHost
					reqDto.ToType = "outbound"
				} else {
					log.Logger.Warn().Err(err).Str("Daddr", skInfo.Daddr).Msg("error getting hostname from ip")
				}
			}
		}
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
		d.Protocol = "HTTPS"
	}

	go func() {
		err := a.ds.PersistRequest(reqDto)
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
