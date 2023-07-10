package aggregator

import (
	"fmt"
	"sort"
	"sync"
)

type TimestampedSocket struct {
	Timestamp uint64    // unix timestamp in milliseconds
	SockInfo  *SockInfo // write as nil on socket close
}

type SocketLine struct {
	mu     sync.RWMutex
	Values []TimestampedSocket
}

// TODO: delete old values
// for memory usage and performance reasons, we should delete old values

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

	// TODO: lru cache, delete old values after a certain time
	// if no new values are added, return from cache
	// A client that uses same socket for a long time will have a lot of requests
	// no need to search for the same value again and again

	return nl.Values[index-1].SockInfo, nil
}
