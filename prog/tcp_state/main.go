// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"alaz/cruntimes"
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kr/pretty"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

const mapKey uint32 = 0

// padding to match the kernel struct
type tcpEvent struct {
	// sample_type int32
	// type_       int32
	// config      int32

	Fd        uint64
	Timestamp uint64
	Type      uint32
	Pid       uint32
	SPort     uint16
	DPort     uint16
	SAddr     [16]byte
	DAddr     [16]byte

	// fd        uint64
	// timestamp uint64
	// ty        uint32 // type
	// pid       uint32
	// sport     uint16
	// dport     uint16
	// saddr     [16]byte
	// daddr     [16]byte
}

func main() {

	// TODO: remove from here, only for testing
	go func() {
		ct, err := cruntimes.NewContainerdTracker()
		if err != nil {
			log.Fatal(err)
		}
		ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
		km, err := ct.ListAll(ctx)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("Running Pods on Node :", len(km.PodMetadatas))
		pretty.Print(km.PodMetadatas)

		fmt.Println("Running Containers on Node:", len(km.ContainerMetadatas))
		pretty.Print(km.ContainerMetadatas)

	}()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// pinning a ebpf program
	// err := objs.bpfPrograms.GetCommand.Pin("/sys/fs/bpf/kprobe_execve_command")
	// if err != nil {
	// 	log.Default().Printf("could not pin program, %v", err)
	// }

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	time.Sleep(1 * time.Second)

	l, err := link.Tracepoint("sock", "inet_sock_set_state", objs.bpfPrograms.InetSockSetState, nil)
	if err != nil {
		log.Fatalf("link inet_sock_set_state tracepoint: %s", err)
	}
	defer l.Close()

	l1, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Fatalf("link sys_enter_connect tracepoint: %s", err)
	}
	defer l1.Close()

	l2, err := link.Tracepoint("syscalls", "sys_exit_connect", objs.bpfPrograms.SysEnterConnect, nil)
	if err != nil {
		log.Fatalf("link sys_exit_connect tracepoint: %s", err)
	}
	defer l2.Close()

	// initialize perf event readers
	tcpListenEvents, err := perf.NewReader(objs.TcpListenEvents, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("error creating perf event array reader: %w", err)
	}
	tcpConnectEvents, err := perf.NewReader(objs.TcpConnectEvents, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("error creating perf event array reader: %w", err)
	}

	go listenDebugMsgs()
	log.Println("Waiting for events..")

	go func() {
		for range ticker.C {
			record, err := tcpListenEvents.Read()
			if err != nil {
				log.Fatalf("error reading from perf array: %w", err)
			}

			if record.LostSamples != 0 {
				log.Printf("lost %d samples", record.LostSamples)
			}

			bpfEvent := (*tcpEvent)(unsafe.Pointer(&record.RawSample[0]))

			log.Printf("--LISTEN EVENT--")
			log.Printf("pid:%d", bpfEvent.Pid)
			log.Printf("sport:%d", bpfEvent.SPort)
			log.Printf("dport:%d", bpfEvent.DPort)
		}
	}()

	go func() {
		for range ticker.C {
			record, err := tcpConnectEvents.Read()
			if err != nil {
				log.Fatalf("error reading from perf array: %w", err)
			}

			if record.LostSamples != 0 {
				log.Printf("lost %d samples", record.LostSamples)
			}

			bpfEvent := (*tcpEvent)(unsafe.Pointer(&record.RawSample[0]))

			if bpfEvent.Type != 3 {
				continue
			}

			log.Printf("--CONNECT EVENT--")
			log.Printf("fd: %d", bpfEvent.Fd)
			log.Printf("timestamp: %d", bpfEvent.Timestamp)
			log.Printf("type: %d", bpfEvent.Type)

			log.Printf("pid: %d", bpfEvent.Pid)
			source := fmt.Sprintf("%d.%d.%d.%d:%d", bpfEvent.SAddr[0], bpfEvent.SAddr[1], bpfEvent.SAddr[2], bpfEvent.SAddr[3], bpfEvent.SPort)
			log.Printf("source: %s", source)

			dest := fmt.Sprintf("%d.%d.%d.%d:%d", bpfEvent.DAddr[0], bpfEvent.DAddr[1], bpfEvent.DAddr[2], bpfEvent.DAddr[3], bpfEvent.DPort)
			log.Printf("dest: %s", dest)
			log.Println()
		}
	}()

	select {}
}

func listenDebugMsgs() {
	printsPath := "/sys/kernel/debug/tracing/trace_pipe"

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	fd, err := os.Open(printsPath)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	buf := make([]byte, 1024)
	for range ticker.C {
		n, err := fd.Read(buf)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("read %d bytes: %s\n", n, buf[:n])
	}
}
