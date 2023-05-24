// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf kprobe.c -- -I../headers

const mapKey uint32 = 0

// padding to match the kernel struct
type commandEvent struct {
	sample_type int32
	type_       int32
	config      int32

	pid     uint32
	uid     uint32
	command [16]byte
	message [16]byte
}

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

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
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	time.Sleep(1 * time.Second)

	kp, err := link.Kprobe(fn, objs.bpfPrograms.GetCommand, nil)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	reader, err := perf.NewReader(objs.Output2, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("error creating perf ring buffer: %w", err)
	}

	go listenDebugMsgs()
	log.Println("Waiting for events..")

	go func() {
		for range ticker.C {
			record, err := reader.Read()
			if err != nil {
				log.Fatalf("error reading from perf array: %w", err)
			}

			if record.LostSamples != 0 {
				log.Printf("lost %d samples", record.LostSamples)
			}

			bpfEvent := (*commandEvent)(unsafe.Pointer(&record.RawSample[0]))

			log.Printf("pid:%d", bpfEvent.pid)
			log.Printf("uid:%d", bpfEvent.uid)
			log.Printf("command:%s", bpfEvent.command)
			log.Printf("message:%s", bpfEvent.message)

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
