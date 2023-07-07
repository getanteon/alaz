package aggregator

import (
	"testing"
)

func TestSocketLine(t *testing.T) {
	sockMap := make(SocketMap)

	var fd uint64 = 6
	sockMap[fd] = &SocketLine{
		Values: []TimestampedSocket{},
	}

	pid := uint32(123)
	// established
	sockMap[fd].AddValue(100, &SockInfo{
		Pid:   pid,
		Fd:    fd,
		Saddr: "saddr1",
	})

	// closed
	sockMap[fd].AddValue(140, nil)

	sockMap[fd].AddValue(200, &SockInfo{
		Pid:   pid,
		Fd:    fd,
		Saddr: "saddr2",
	})

	sockMap[fd].AddValue(300, &SockInfo{
		Pid:   pid,
		Fd:    fd,
		Saddr: "saddr3",
	})

	si, err := sockMap[fd].GetValue(130)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
		return
	}

	if si.Saddr != "saddr1" {
		t.Fatalf("unexpected saddr: %v", si.Saddr)
	}

	si, err = sockMap[fd].GetValue(143)
	if err == nil {
		t.Fatalf("expected error")
		return
	}

	si, err = sockMap[fd].GetValue(400)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
		return
	}

	if si.Saddr != "saddr3" {
		t.Fatalf("unexpected saddr: %v", si.Saddr)
	}

}
