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

	processedFds map[uint64]struct{}
	closeCh      chan struct{}
	ctx          context.Context
}

// only one worker can create socket lines for a particular process(socketmap)
func (sm *SocketMap) ProcessSocketLineCreationRequests() {
	for {
		select {
		case <-sm.closeCh:
			return
		case fd := <-sm.waitingFds:
			log.Logger.Debug().Ctx(sm.ctx).
				Msgf("pid=%d,fd=%d came for socket line creation", sm.pid, fd)
			if _, ok := sm.M[fd]; !ok {
				sm.createSocketLine(fd)
				log.Logger.Info().Ctx(sm.ctx).
					Uint32("pid", sm.pid).
					Uint64("fd", fd).
					Msgf("created socket line for fd:%d", fd)
			}
		}
	}
}

func (sm *SocketMap) SignalSocketLine(ctx context.Context, fd uint64) {
	if _, ok := sm.processedFds[fd]; ok {
		return
	}
	log.Logger.Debug().Ctx(ctx).Uint32("pid", sm.pid).Uint64("fd", fd).Msg("signaling socket creation..")
	sm.processedFds[fd] = struct{}{}
	sm.waitingFds <- fd
}

func (sm *SocketMap) createSocketLine(fd uint64) {
	// TODO: get fetch boolean
	log.Logger.Debug().Ctx(sm.ctx).
		Uint32("pid", sm.pid).
		Uint64("fd", fd).
		Msg("createSocketLine called..")
	skLine := NewSocketLine(sm.ctx, sm.pid, fd, true)
	log.Logger.Debug().Ctx(sm.ctx).
		Uint32("pid", sm.pid).
		Uint64("fd", fd).
		Msg("createSocketLine acquiring lock..")
	sm.mu.Lock()
	log.Logger.Debug().Ctx(sm.ctx).
		Uint32("pid", sm.pid).
		Uint64("fd", fd).
		Msg("createSocketLine inside lock..")
	sm.M[fd] = skLine
	sm.mu.Unlock()
	log.Logger.Debug().Ctx(sm.ctx).
		Uint32("pid", sm.pid).
		Uint64("fd", fd).
		Msg("createSocketLine ended..")
}

// get all tcp sockets for the pid
// iterate through all sockets
// create a new socket line for each socket
// add it to the socket map
// func (sm *SocketMap) fetchExistingSockets() {
// 	socks := map[string]sock{}

// 	// Get the sockets for the process.
// 	var err error
// 	for _, f := range []string{"tcp", "tcp6"} {
// 		sockPath := strings.Join([]string{"/proc", fmt.Sprint(sm.pid), "net", f}, "/")

// 		ss, err := readSockets(sockPath)
// 		if err != nil {
// 			continue
// 		}

// 		for _, s := range ss {
// 			socks[s.Inode] = sock{TcpSocket: s}
// 		}
// 	}

// 	// Get the file descriptors for the process.
// 	fdDir := strings.Join([]string{"/proc", fmt.Sprint(sm.pid), "fd"}, "/")
// 	fdEntries, err := os.ReadDir(fdDir)
// 	if err != nil {
// 		return
// 	}

// 	fds := make([]Fd, 0, len(fdEntries))
// 	for _, entry := range fdEntries {
// 		fd, err := strconv.ParseUint(entry.Name(), 10, 64)
// 		if err != nil {
// 			continue
// 		}
// 		dest, err := os.Readlink(path.Join(fdDir, entry.Name()))
// 		if err != nil {
// 			continue
// 		}
// 		var socketInode string
// 		if strings.HasPrefix(dest, "socket:[") && strings.HasSuffix(dest, "]") {
// 			socketInode = dest[len("socket:[") : len(dest)-1]
// 		}
// 		fds = append(fds, Fd{Fd: fd, Dest: dest, SocketInode: socketInode})
// 	}

// 	// Match the sockets to the file descriptors.
// 	for _, fd := range fds {
// 		if fd.SocketInode != "" {
// 			// add to values
// 			s := socks[fd.SocketInode].TcpSocket
// 			sockInfo := &SockInfo{
// 				Pid:   sm.pid,
// 				Fd:    fd.Fd,
// 				Saddr: s.SAddr.IP().String(),
// 				Sport: s.SAddr.Port(),
// 				Daddr: s.DAddr.IP().String(),
// 				Dport: s.DAddr.Port(),
// 			}

// 			if sockInfo.Saddr == "zero IP" || sockInfo.Daddr == "zero IP" || sockInfo.Sport == 0 || sockInfo.Dport == 0 {
// 				continue
// 			}

// 			skLine := NewSocketLine(sm.pid, fd.Fd)
// 			skLine.AddValue(0, sockInfo)

// 			if sm.mu == nil {
// 				return
// 			}

// 			sm.mu.Lock()
// 			if sm.M == nil {
// 				sm.M = make(map[uint64]*SocketLine)
// 			}
// 			sm.M[fd.Fd] = skLine
// 			sm.mu.Unlock()
// 		}
// 	}
// }

// func (sm *SocketMap) retrieveSocket(fd uint64) {
// 	sm.mu.Lock()
// 	if sl, ok := sm.M[fd]; ok {
// 		sl.getConnectionInfo()
// 	} else {
// 		sm.M[fd] = NewSocketLine(sm.pid, fd)
// 		sl.getConnectionInfo()
// 	}
// 	sm.mu.Unlock()
// }
