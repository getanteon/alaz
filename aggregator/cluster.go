package aggregator

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ddosify/alaz/log"
	"k8s.io/apimachinery/pkg/types"
)

type ClusterInfo struct {
	k8smu                 sync.RWMutex
	PodIPToPodUid         map[string]types.UID `json:"podIPToPodUid"`
	ServiceIPToServiceUid map[string]types.UID `json:"serviceIPToServiceUid"`

	// Pid -> SocketMap
	// pid -> fd -> {saddr, sport, daddr, dport}
	SocketMaps   []*SocketMap // index symbolizes pid
	socketMapsmu sync.Mutex

	// Below mutexes guard socketMaps, set to mu inside SocketMap struct
	// Used to find the correct mutex for the process, some pids can share the same mutex
	muIndex atomic.Uint64
	muArray []*sync.RWMutex

	signalChan chan uint32 // pids are signaled on this channel to notify clusterInfo struct to initialize a SocketMap
}

func newClusterInfo(liveProcCount int) *ClusterInfo {
	ci := &ClusterInfo{
		PodIPToPodUid:         map[string]types.UID{},
		ServiceIPToServiceUid: map[string]types.UID{},
	}
	ci.signalChan = make(chan uint32)
	sockMaps := make([]*SocketMap, maxPid+1) // index=pid
	ci.SocketMaps = sockMaps
	ci.muIndex = atomic.Uint64{}

	// initialize mutex array

	// normally, mutex per pid is straightforward solution
	// on regular systems, maxPid is around 32768
	// so, we allocate 32768 mutexes, which is 32768 * 24 bytes = 786KB
	// but on 64-bit systems, maxPid can be 4194304
	// and we don't want to allocate 4194304 mutexes, it adds up to 4194304 * 24 bytes = 100MB
	// So, some process will have to share the mutex

	// assume liveprocesses can increase up to 100 times of current count
	// if processes exceeds the count of mutex, they will share the mutex
	countMuArray := liveProcCount * 100
	if countMuArray > maxPid {
		countMuArray = maxPid
	}
	// for 2k processes, 200k mutex => 200k * 24 bytes = 4.80MB
	// in case of maxPid is 32678, 32678 * 24 bytes = 784KB, pick the smaller one
	ci.muArray = make([]*sync.RWMutex, countMuArray)
	go ci.handleSocketMapCreation()
	return ci
}

func (ci *ClusterInfo) SignalSocketMapCreation(pid uint32) {
	ci.signalChan <- pid
}

// events will be processed sequentially here in one goroutine.
// in order to prevent race.
func (ci *ClusterInfo) handleSocketMapCreation() {
	for pid := range ci.signalChan {
		ctxPid := context.WithValue(context.Background(), log.LOG_CONTEXT, fmt.Sprint(pid))

		if ci.SocketMaps[pid] != nil {
			continue
		}

		sockMap := &SocketMap{
			mu:             nil, // set below
			pid:            pid,
			M:              map[uint64]*SocketLine{},
			waitingFds:     make(chan uint64, 1000),
			processedFds:   map[uint64]struct{}{},
			processedFdsmu: sync.RWMutex{},
			closeCh:        make(chan struct{}, 1),
			ctx:            ctxPid,
		}

		ci.muIndex.Add(1)
		i := (ci.muIndex.Load()) % uint64(len(ci.muArray))
		ci.muArray[i] = &sync.RWMutex{}
		sockMap.mu = ci.muArray[i]
		ci.SocketMaps[pid] = sockMap
		go sockMap.ProcessSocketLineCreationRequests()
	}
}

func (ci *ClusterInfo) clearProc(pid uint32) {
	sm := ci.SocketMaps[pid]
	if sm == nil {
		return
	}

	// stop waiting for socketline creation requests
	sm.mu.Lock()
	sm.closeCh <- struct{}{}
	sm.M = nil
	sm.mu.Unlock()

	// reset
	ci.SocketMaps[pid] = nil
}
