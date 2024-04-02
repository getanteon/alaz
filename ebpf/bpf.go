package ebpf

import "context"

type Program interface {
	Attach()                                          // attach links to programs, in case error process must exit
	InitMaps()                                        // initialize bpf map readers, must be called before Consume
	Consume(ctx context.Context, ch chan interface{}) // consume bpf events, publishes to chan provided
	Close()                                           // release resources
}
