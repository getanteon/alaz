package ebpf

import "alaz/ebpf/tcp_state"

// TODO: type
var EbpfEvents chan interface{}

func init() {
	EbpfEvents = make(chan interface{}, 1000) // TODO: make configurable
}

func Deploy() {
	tcp_state.Deploy(EbpfEvents)
}
