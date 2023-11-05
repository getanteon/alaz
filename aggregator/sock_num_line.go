package aggregator

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ddosify/alaz/log"

	"inet.af/netaddr"
)

type TimestampedSocket struct {
	Timestamp uint64    // unix timestamp in milliseconds
	LastMatch uint64    // last time this socket was matched on user space (request_time + process_latency)
	SockInfo  *SockInfo // write as nil on socket close
}

type SocketLine struct {
	mu     sync.RWMutex
	pid    uint32
	fd     uint64
	Values []TimestampedSocket
}

func NewSocketLine(pid uint32, fd uint64) *SocketLine {
	skLine := &SocketLine{
		mu:     sync.RWMutex{},
		pid:    pid,
		fd:     fd,
		Values: make([]TimestampedSocket, 0),
	}
	go skLine.DeleteUnused()

	return skLine
}

func (nl *SocketLine) AddValue(timestamp uint64, sockInfo *SockInfo) {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	nl.Values = insertIntoSortedSlice(nl.Values, TimestampedSocket{Timestamp: timestamp, SockInfo: sockInfo})
}

func (nl *SocketLine) GetValue(timestamp uint64) (*SockInfo, error) {
	nl.mu.RLock()
	defer nl.mu.RUnlock()

	if len(nl.Values) == 0 {
		return nil, fmt.Errorf("sock line is empty")
	}

	index := sort.Search(len(nl.Values), func(i int) bool {
		return !(nl.Values[i].Timestamp < timestamp)
	})

	if index == len(nl.Values) {
		// The timestamp is after the last entry, so return the last value
		nl.Values[index-1].LastMatch = uint64(time.Now().UnixNano())
		return nl.Values[len(nl.Values)-1].SockInfo, nil
	}

	if index == 0 {
		// The timestamp is before or equal to the first entry, so return an error
		return nil, fmt.Errorf("no smaller value found")
	}

	si := nl.Values[index-1].SockInfo

	if si == nil {
		// The timestamp is exactly on a socket close
		return nil, fmt.Errorf("closed socket")
	}

	// Return the value associated with the closest previous timestamp

	nl.Values[index-1].LastMatch = uint64(time.Now().UnixNano())
	return nl.Values[index-1].SockInfo, nil
}

func (nl *SocketLine) DeleteUnused() {
	// Delete socket lines that are not in use
	nl.mu.Lock()
	defer nl.mu.Unlock()

	if len(nl.Values) == 0 {
		return
	}

	var lastMatchedReqTime uint64 = 0

	// traverse the slice backwards
	for i := len(nl.Values) - 1; i >= 0; i-- {
		if nl.Values[i].LastMatch != 0 && nl.Values[i].LastMatch > lastMatchedReqTime {
			lastMatchedReqTime = nl.Values[i].LastMatch
		}
	}

	if lastMatchedReqTime == 0 {
		return
	}

	// assumedInterval is inversely proportional to the number of requests being discarded
	assumedInterval := uint64(5 * time.Minute)

	// delete all values that
	// closed and its LastMatch + assumedInterval < lastMatchedReqTime
	for i := len(nl.Values) - 1; i >= 1; i-- {
		if nl.Values[i].SockInfo == nil &&
			nl.Values[i-1].SockInfo != nil &&
			nl.Values[i-1].LastMatch+assumedInterval < lastMatchedReqTime {

			// delete these two values
			nl.Values = append(nl.Values[:i-1], nl.Values[i+1:]...)
			i-- // we deleted two values, so we need to decrement i by 2
		}
	}

}

func (nl *SocketLine) GetAlreadyExistingSockets() {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	log.Logger.Debug().Msgf("getting already existing sockets for pid %d, fd %d", nl.pid, nl.fd)

	socks := map[string]sock{}

	// Get the sockets for the process.
	var err error
	for _, f := range []string{"tcp", "tcp6"} {
		sockPath := strings.Join([]string{"/proc", fmt.Sprint(nl.pid), "net", f}, "/")

		ss, err := readSockets(sockPath)
		if err != nil {

			continue
		}

		for _, s := range ss {
			socks[s.Inode] = sock{TcpSocket: s}
		}
	}

	// Get the file descriptors for the process.
	fdDir := strings.Join([]string{"/proc", fmt.Sprint(nl.pid), "fd"}, "/")
	fdEntries, err := os.ReadDir(fdDir)
	if err != nil {
		log.Logger.Warn().Err(err).Msgf("failed to read directory %s", fdDir)
		return
	}

	fds := make([]Fd, 0, len(fdEntries))
	for _, entry := range fdEntries {
		fd, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil {
			log.Logger.Warn().Err(err).Uint32("pid", nl.pid).
				Uint64("fd", nl.fd).Msgf("failed to parse %s as uint", entry.Name())
			continue
		}
		dest, err := os.Readlink(path.Join(fdDir, entry.Name()))
		if err != nil {
			log.Logger.Warn().Err(err).
				Uint32("pid", nl.pid).
				Uint64("fd", nl.fd).Msgf("failed to read link %s", path.Join(fdDir, entry.Name()))
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
		if fd.SocketInode != "" && nl.fd == fd.Fd {
			// add to values
			s := socks[fd.SocketInode].TcpSocket
			ts := TimestampedSocket{
				Timestamp: 0, // start time unknown
				LastMatch: 0,
				SockInfo: &SockInfo{
					Pid:   nl.pid,
					Fd:    fd.Fd,
					Saddr: s.SAddr.IP().String(),
					Sport: s.SAddr.Port(),
					Daddr: s.DAddr.IP().String(),
					Dport: s.DAddr.Port(),
				},
			}
			log.Logger.Debug().Any("skInfo", ts).Uint32("pid", nl.pid).
				Uint64("fd", nl.fd).Msg("adding already established socket")
			nl.Values = append(nl.Values, ts)
		}
	}
}

type sock struct {
	pid uint32
	fd  uint64
	TcpSocket
}

type TcpSocket struct {
	Inode  string
	SAddr  netaddr.IPPort
	DAddr  netaddr.IPPort
	Listen bool
}

func readSockets(src string) ([]TcpSocket, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var res []TcpSocket
	scanner := bufio.NewScanner(f)
	header := true
	for scanner.Scan() {
		if header {
			header = false
			continue
		}

		//
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 10 {
			continue
		}

		//    local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
		// 0: 7038A8C0:A24A C28D640A:0050 01 00000000:00000000 02:000002E0 00000000 0 0 5276530 2 ffff8e8be7a0bd40 20 4 24 10 -1
		// 	  192.168.56.112:41546 -> 10.100.141.194:80
		localX := fields[1]
		remoteX := fields[2]
		stateX := fields[3]
		inodeX := fields[9]

		if stateX != stateEstablished && stateX != stateListen {
			continue
		}

		res = append(res, TcpSocket{SAddr: decodeAddr([]byte(localX)), DAddr: decodeAddr([]byte(remoteX)), Listen: stateX == stateListen, Inode: inodeX})
	}
	return res, nil
}

func decodeAddr(src []byte) netaddr.IPPort {
	col := bytes.IndexByte(src, ':')
	if col == -1 || (col != 8 && col != 32) {
		return netaddr.IPPort{}
	}

	ip := make([]byte, col/2)
	if _, err := hex.Decode(ip, src[:col]); err != nil {
		return netaddr.IPPort{}
	}
	port := make([]byte, 2)
	if _, err := hex.Decode(port, src[col+1:]); err != nil {
		return netaddr.IPPort{}
	}

	var v uint32
	for i := 0; i < len(ip); i += 4 {
		v = binary.BigEndian.Uint32(ip[i : i+4])
		binary.LittleEndian.PutUint32(ip[i:i+4], v)
	}

	ipp, ok := netaddr.FromStdIP(net.IP(ip))
	if !ok {
		return netaddr.IPPort{}
	}
	return netaddr.IPPortFrom(ipp, binary.BigEndian.Uint16(port))
}

type Fd struct {
	Fd   uint64
	Dest string

	SocketInode string
}

const (
	stateEstablished = "01"
	stateListen      = "0A"
)

func insertIntoSortedSlice(sortedSlice []TimestampedSocket, newItem TimestampedSocket) []TimestampedSocket {
	idx := sort.Search(len(sortedSlice), func(i int) bool {
		return sortedSlice[i].Timestamp >= newItem.Timestamp
	})

	// Insert the new item at the correct position.
	sortedSlice = append(sortedSlice, TimestampedSocket{})
	copy(sortedSlice[idx+1:], sortedSlice[idx:])
	sortedSlice[idx] = newItem

	return sortedSlice
}
