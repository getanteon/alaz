package aggregator

import (
	"context"
	"sync"

	"github.com/ddosify/alaz/log"
)

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
	mu         *sync.RWMutex
	pid        uint32
	M          map[uint64]*SocketLine `json:"fdToSockLine"` // fd -> SockLine
	waitingFds chan uint64

	processedFds   map[uint64]struct{}
	processedFdsmu sync.RWMutex
	closeCh        chan struct{}
	ctx            context.Context
}

// only one worker can create socket lines for a particular process(socketmap)
func (sm *SocketMap) ProcessSocketLineCreationRequests() {
	for {
		select {
		case <-sm.closeCh:
			return
		case fd := <-sm.waitingFds:
			if _, ok := sm.M[fd]; !ok {
				sm.createSocketLine(fd, true)
				log.Logger.Debug().Ctx(sm.ctx).
					Uint32("pid", sm.pid).
					Uint64("fd", fd).
					Msgf("created socket line for fd:%d", fd)
			}
		}
	}
}

func (sm *SocketMap) SignalSocketLine(ctx context.Context, fd uint64) {
	sm.processedFdsmu.RLock()
	if _, ok := sm.processedFds[fd]; ok {
		sm.processedFdsmu.RUnlock()
		return
	} else {
		sm.processedFdsmu.RUnlock()

		sm.processedFdsmu.Lock()
		sm.processedFds[fd] = struct{}{}
		sm.processedFdsmu.Unlock()
	}

	sm.waitingFds <- fd
}

func (sm *SocketMap) createSocketLine(fd uint64, fetch bool) {
	skLine := NewSocketLine(sm.ctx, sm.pid, fd, fetch)
	sm.mu.Lock()
	sm.M[fd] = skLine
	sm.mu.Unlock()
}
