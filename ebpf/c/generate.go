package c

import (
	"github.com/ddosify/alaz/log"

	"github.com/cilium/ebpf/linux"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bpf.c -- -I../headers

var BpfObjs bpfObjects

func Load() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Load pre-compiled programs and maps into the kernel.
	BpfObjs = bpfObjects{}
	if err := loadBpfObjects(&BpfObjs, nil); err != nil {
		log.Logger.Fatal().Err(err).Msg("loading objects")
	}

	linux.FlushCaches()
}
