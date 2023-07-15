package aggregator

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type TimestampedSocket struct {
	Timestamp uint64    // unix timestamp in milliseconds
	LastMatch uint64    // last time this socket was matched on user space (request_time + process_latency)
	SockInfo  *SockInfo // write as nil on socket close
}

type SocketLine struct {
	mu     sync.RWMutex
	Values []TimestampedSocket
}

func NewSocketLine() *SocketLine {
	skLine := &SocketLine{
		mu:     sync.RWMutex{},
		Values: make([]TimestampedSocket, 0),
	}
	go skLine.DeleteUnused()

	return skLine
}

func (nl *SocketLine) AddValue(timestamp uint64, sockInfo *SockInfo) {
	nl.mu.Lock()
	defer nl.mu.Unlock()
	nl.Values = append(nl.Values, TimestampedSocket{Timestamp: timestamp, SockInfo: sockInfo})
	sort.Slice(nl.Values, func(i, j int) bool {
		return nl.Values[i].Timestamp < nl.Values[j].Timestamp
	})
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

	// TODO: lru cache
	// if no new values are added, return from cache
	// A client that uses same socket for a long time will have a lot of requests
	// no need to search for the same value again and again

	nl.Values[index-1].LastMatch = uint64(time.Now().UnixNano())
	return nl.Values[index-1].SockInfo, nil
}

func (nl *SocketLine) DeleteUnused() {
	// Delete socket lines that are not in use
	ticker := time.NewTicker(1 * time.Minute)

	for range ticker.C {
		func() {
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
			assumedInterval := uint64(5 * time.Minute) // TODO: make configurable

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
		}()
	}
}
