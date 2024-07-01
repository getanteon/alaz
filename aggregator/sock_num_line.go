package aggregator

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
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

	return skLine
}

func (nl *SocketLine) AddValue(timestamp uint64, sockInfo *SockInfo) {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	// ignore close events
	if sockInfo == nil {
		return
	}

	// if last element is equal to the current element, ignore
	if len(nl.Values) > 0 {
		last := nl.Values[len(nl.Values)-1].SockInfo
		if last != nil && last.Saddr == sockInfo.Saddr && last.Sport == sockInfo.Sport && last.Daddr == sockInfo.Daddr && last.Dport == sockInfo.Dport {
			return
		}
	}

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

	if len(nl.Values) <= 1 {
		return
	}

	// if two open sockets are alined, delete the first one
	// in case first ones close event did not arrive
	result := make([]TimestampedSocket, 0)
	i := 0
	for i < len(nl.Values)-1 {
		if nl.Values[i].SockInfo != nil && nl.Values[i+1].SockInfo != nil {
			result = append(result, nl.Values[i+1])
			i = i + 2
		} else {
			result = append(result, nl.Values[i])
			i++
		}
	}
	nl.Values = result

	var lastMatchedReqTime uint64 = 0

	// traverse the slice backwards
	for i := len(nl.Values) - 1; i >= 0; i-- {
		if nl.Values[i].LastMatch != 0 && nl.Values[i].LastMatch > lastMatchedReqTime {
			lastMatchedReqTime = nl.Values[i].LastMatch
		}
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

		saddr, err := decodeAddr([]byte(localX))
		if err != nil {
			continue
		}
		daddr, _ := decodeAddr([]byte(remoteX))
		if err != nil {
			continue
		}

		res = append(res, TcpSocket{SAddr: saddr, DAddr: daddr, Listen: stateX == stateListen, Inode: inodeX})
	}
	return res, nil
}

func decodeAddr(src []byte) (netaddr.IPPort, error) {
	col := bytes.IndexByte(src, ':')
	if col == -1 || (col != 8 && col != 32) {
		return netaddr.IPPort{}, fmt.Errorf("invalid address %q", src)
	}

	ip := make([]byte, col/2)
	if _, err := hex.Decode(ip, src[:col]); err != nil {
		return netaddr.IPPort{}, fmt.Errorf("invalid address %q: %v", src, err)
	}
	port := make([]byte, 2)
	if _, err := hex.Decode(port, src[col+1:]); err != nil {
		return netaddr.IPPort{}, fmt.Errorf("invalid address %q: %v", src, err)
	}

	var v uint32
	for i := 0; i < len(ip); i += 4 {
		v = binary.BigEndian.Uint32(ip[i : i+4])
		binary.LittleEndian.PutUint32(ip[i:i+4], v)
	}

	ipp, ok := netaddr.FromStdIP(net.IP(ip))
	if !ok {
		return netaddr.IPPort{}, fmt.Errorf("invalid address %q", src)
	}
	return netaddr.IPPortFrom(ipp, binary.BigEndian.Uint16(port)), nil
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

// reverse slice
func reverseSlice(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// convertHexToIP converts a hex string IP address to a human-readable IP address.
func convertHexToIP(hex string) string {
	var ipParts []string
	for i := 0; i < len(hex); i += 2 {
		part, _ := strconv.ParseInt(hex[i:i+2], 16, 64)
		ipParts = append(ipParts, fmt.Sprintf("%d", part))
	}
	ipParts = reverseSlice(ipParts)
	return strings.Join(ipParts, ".")
}

// convertHexToPort converts a hex string port to a human-readable port.
func convertHexToPort(hex string) int {
	port, _ := strconv.ParseInt(hex, 16, 64)
	if port < 0 || port > 65535 {
		return 0
	}
	return int(port)
}

func getInodeFromFD(pid, fd string) (string, error) {
	fdPath := fmt.Sprintf("/proc/%s/fd/%s", pid, fd)
	link, err := os.Readlink(fdPath)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`socket:\[(\d+)\]`)
	match := re.FindStringSubmatch(link)
	if len(match) < 2 {
		return "", fmt.Errorf("no inode found in link: %s", link)
	}

	return match[1], nil
}

func findTCPConnection(inode string, pid string) (string, error) {
	tcpFile, err := os.Open(fmt.Sprintf("/proc/%s/net/tcp", pid))
	if err != nil {
		return "", err
	}
	defer tcpFile.Close()

	scanner := bufio.NewScanner(tcpFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, inode) {
			return line, nil
		}
	}

	return "", fmt.Errorf("no TCP connection found for inode %s", inode)
}

func parseTcpLine(line string) (localIP string, localPort int, remoteIP string, remotePort int) {
	fields := strings.Fields(line)
	localAddress := fields[1]
	remoteAddress := fields[2]

	localIP = convertHexToIP(localAddress[:8])
	localPort = convertHexToPort(localAddress[9:])
	remoteIP = convertHexToIP(remoteAddress[:8])
	remotePort = convertHexToPort(remoteAddress[9:])

	return
}

func (nl *SocketLine) getConnectionInfo() error {
	nl.mu.Lock()
	defer nl.mu.Unlock()

	inode, err := getInodeFromFD(fmt.Sprintf("%d", nl.pid), fmt.Sprintf("%d", nl.fd))
	if err != nil {
		return err
	}

	connectionInfo, err := findTCPConnection(inode, fmt.Sprintf("%d", nl.pid))
	if err != nil {
		return err
	}

	localIP, localPort, remoteIP, remotePort := parseTcpLine(connectionInfo)

	skInfo := &SockInfo{
		Pid:   nl.pid,
		Fd:    nl.fd,
		Saddr: localIP,
		Sport: uint16(localPort),
		Daddr: remoteIP,
		Dport: uint16(remotePort),
	}

	// add to socket line
	// convert to bpf time
	log.Logger.Debug().Msgf("Adding socket line read from user space %v", skInfo)
	nl.AddValue(convertUserTimeToKernelTime(uint64(time.Now().UnixNano())), skInfo)
	return nil
}
