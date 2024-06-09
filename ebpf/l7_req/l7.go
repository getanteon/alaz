package l7_req

import (
	"bytes"
	"context"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/ddosify/alaz/ebpf/c"
	"github.com/ddosify/alaz/log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

// match with values in l7_req.c
const (
	BPF_L7_PROTOCOL_UNKNOWN = iota
	BPF_L7_PROTOCOL_HTTP
	BPF_L7_PROTOCOL_AMQP
	BPF_L7_PROTOCOL_POSTGRES
	BPF_L7_PROTOCOL_HTTP2
	BPF_L7_PROTOCOL_REDIS
)

// for user space
const (
	L7_PROTOCOL_HTTP     = "HTTP"
	L7_PROTOCOL_HTTP2    = "HTTP2"
	L7_PROTOCOL_AMQP     = "AMQP"
	L7_PROTOCOL_POSTGRES = "POSTGRES"
	L7_PROTOCOL_REDIS    = "REDIS"
	L7_PROTOCOL_UNKNOWN  = "UNKNOWN"
)

// Custom type for the enumeration
type L7ProtocolConversion uint32

// String representation of the enumeration values
func (e L7ProtocolConversion) String() string {
	switch e {
	case BPF_L7_PROTOCOL_HTTP:
		return L7_PROTOCOL_HTTP
	case BPF_L7_PROTOCOL_AMQP:
		return L7_PROTOCOL_AMQP
	case BPF_L7_PROTOCOL_POSTGRES:
		return L7_PROTOCOL_POSTGRES
	case BPF_L7_PROTOCOL_HTTP2:
		return L7_PROTOCOL_HTTP2
	case BPF_L7_PROTOCOL_REDIS:
		return L7_PROTOCOL_REDIS
	case BPF_L7_PROTOCOL_UNKNOWN:
		return L7_PROTOCOL_UNKNOWN
	default:
		return "Unknown"
	}
}

// match with values in l7_req.c, order is important
const (
	BPF_METHOD_UNKNOWN = iota
	BPF_METHOD_GET
	BPF_METHOD_POST
	BPF_METHOD_PUT
	BPF_METHOD_PATCH
	BPF_METHOD_DELETE
	BPF_METHOD_HEAD
	BPF_METHOD_CONNECT
	BPF_METHOD_OPTIONS
	BPF_METHOD_TRACE
)

const (
	BPF_HTTP2_METHOD_UNKNOWN = iota
	BPF_HTTP2_METHOD_CLIENT
	BPF_HTTP2_METHOD_SERVER
)

// match with values in l7_req.c, order is important
const (
	BPF_AMQP_METHOD_UNKNOWN = iota
	BPF_AMQP_METHOD_PUBLISH
	BPF_AMQP_METHOD_DELIVER
)

// match with values in l7_req.c, order is important
const (
	BPF_POSTGRES_METHOD_UNKNOWN = iota
	BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE
	BPF_POSTGRES_METHOD_SIMPLE_QUERY
	BPF_POSTGRES_METHOD_EXTENDED_QUERY // for prepared statements

	// BPF_POSTGRES_METHOD_QUERY
	// BPF_POSTGRES_METHOD_EXECUTE
	// BPF_POSTGRES_METHOD_PARSE
	// BPF_POSTGRES_METHOD_BIND
	// BPF_POSTGRES_METHOD_DESCRIBE
	// BPF_POSTGRES_METHOD_SYNC
	// BPF_POSTGRES_METHOD_FLUSH
	// BPF_POSTGRES_METHOD_CONSUME
	// BPF_POSTGRES_METHOD_PARSE_COMPLETE
	// BPF_POSTGRES_METHOD_BIND_COMPLETE
	// BPF_POSTGRES_METHOD_CLOSE_COMPLETE
	// BPF_POSTGRES_METHOD_SYNC_COMPLETE
	// BPF_POSTGRES_METHOD_READY_FOR_QUERY
	//...
)

// match with values in l7.c, order is important
const (
	BPF_REDIS_METHOD_UNKNOWN = iota
	METHOD_REDIS_COMMAND
	METHOD_REDIS_PUSHED_EVENT
	METHOD_REDIS_PING
)

// for http, user space
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	PATCH   = "PATCH"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	CONNECT = "CONNECT"
	OPTIONS = "OPTIONS"
	TRACE   = "TRACE"
)

// for rabbitmq, user space
const (
	PUBLISH = "PUBLISH"
	DELIVER = "DELIVER"
)

// for postgres, user space
const (
	CLOSE_OR_TERMINATE = "CLOSE_OR_TERMINATE"
	SIMPLE_QUERY       = "SIMPLE_QUERY"
	EXTENDED_QUERY     = "EXTENDED_QUERY"
)

// for http2, user space
const (
	CLIENT_FRAME = "CLIENT_FRAME"
	SERVER_FRAME = "SERVER_FRAME"
)

// for http2, user space
const (
	REDIS_COMMAND      = "COMMAND"
	REDIS_PUSHED_EVENT = "PUSHED_EVENT"
	REDIS_PING         = "PING"
)

// Custom type for the enumeration
type HTTPMethodConversion uint32

// String representation of the enumeration values
func (e HTTPMethodConversion) String() string {
	switch e {
	case BPF_METHOD_GET:
		return GET
	case BPF_METHOD_POST:
		return POST
	case BPF_METHOD_PUT:
		return PUT
	case BPF_METHOD_PATCH:
		return PATCH
	case BPF_METHOD_DELETE:
		return DELETE
	case BPF_METHOD_HEAD:
		return HEAD
	case BPF_METHOD_CONNECT:
		return CONNECT
	case BPF_METHOD_OPTIONS:
		return OPTIONS
	case BPF_METHOD_TRACE:
		return TRACE
	default:
		return "Unknown"
	}
}

// Custom type for the enumeration
type RabbitMQMethodConversion uint32

// String representation of the enumeration values
func (e RabbitMQMethodConversion) String() string {
	switch e {
	case BPF_AMQP_METHOD_PUBLISH:
		return PUBLISH
	case BPF_AMQP_METHOD_DELIVER:
		return DELIVER
	default:
		return "Unknown"
	}
}

// Custom type for the enumeration
type PostgresMethodConversion uint32

// String representation of the enumeration values
func (e PostgresMethodConversion) String() string {
	switch e {
	case BPF_POSTGRES_METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE:
		return CLOSE_OR_TERMINATE
	case BPF_POSTGRES_METHOD_SIMPLE_QUERY:
		return SIMPLE_QUERY
	case BPF_POSTGRES_METHOD_EXTENDED_QUERY:
		return EXTENDED_QUERY
	default:
		return "Unknown"
	}
}

// Custom type for the enumeration
type Http2MethodConversion uint32

// String representation of the enumeration values
func (e Http2MethodConversion) String() string {
	switch e {
	case BPF_HTTP2_METHOD_CLIENT:
		return CLIENT_FRAME
	case BPF_HTTP2_METHOD_SERVER:
		return SERVER_FRAME
	default:
		return "Unknown"
	}
}

// Custom type for the enumeration
type RedisMethodConversion uint32

// String representation of the enumeration values
func (e RedisMethodConversion) String() string {
	switch e {
	case METHOD_REDIS_COMMAND:
		return REDIS_COMMAND
	case METHOD_REDIS_PUSHED_EVENT:
		return REDIS_PUSHED_EVENT
	case METHOD_REDIS_PING:
		return REDIS_PING
	default:
		return "Unknown"
	}
}

var FirstKernelTime uint64 = 0 // nanoseconds since boot
var FirstUserspaceTime uint64 = 0

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
// // go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf l7.c -- -I../headers

// bpf structs, copy from generated code
type bpfLogMessage struct {
	Level    uint32
	LogMsg   [100]uint8
	FuncName [100]uint8
	Pid      uint32
	Arg1     uint64
	Arg2     uint64
	Arg3     uint64
}

type bpfL7Event struct {
	Fd                  uint64
	WriteTimeNs         uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            uint8
	Method              uint8
	Padding             uint16
	Payload             [1024]uint8
	PayloadSize         uint32
	PayloadReadComplete uint8
	Failed              uint8
	IsTls               uint8
	_                   [1]byte
	Seq                 uint32
	Tid                 uint32
	_                   [4]byte
}

type bpfTraceEvent struct {
	Pid   uint32
	Tid   uint32
	Tx    uint64
	Type_ uint8
	_     [3]byte
	Seq   uint32
}

type TraceEvent struct {
	Pid   uint32
	Tid   uint32
	Tx    int64
	Type_ uint8
	Seq   uint32
}

const TRACE_EVENT = "trace_event"

func (e TraceEvent) Type() string {
	return TRACE_EVENT
}

// for user space
type L7Event struct {
	Fd                  uint64
	Pid                 uint32
	Status              uint32
	Duration            uint64
	Protocol            string // L7_PROTOCOL_HTTP
	Tls                 bool   // Whether request was encrypted
	Method              string
	Payload             [1024]uint8
	PayloadSize         uint32 // How much of the payload was copied
	PayloadReadComplete bool   // Whether the payload was copied completely
	Failed              bool   // Request failed
	WriteTimeNs         uint64 // start time of write syscall
	Tid                 uint32
	Seq                 uint32 // tcp seq num
}

const L7_EVENT = "l7_event"

func (e *L7Event) Type() string {
	return L7_EVENT
}

type L7ProgConfig struct {
	TrafficBpfMapSize  uint32 // specified in terms of os page size
	L7EventsBpfMapSize uint32 // specified in terms of os page size
	LogsBpfMapSize     uint32
}

var defaultConfig *L7ProgConfig = &L7ProgConfig{
	TrafficBpfMapSize:  4096,
	L7EventsBpfMapSize: 4096,
	LogsBpfMapSize:     4,
}

type L7Prog struct {
	// links represent a program attached to a hook
	links map[string]link.Link // key : hook name

	l7Events *perf.Reader
	logs     *perf.Reader
	traffic  *perf.Reader // ingress-egress calls

	l7EventsMapSize uint32
	trafficMapSize  uint32
	logsMapsSize    uint32
}

func InitL7Prog(conf *L7ProgConfig) *L7Prog {
	if conf == nil {
		conf = defaultConfig
	}

	return &L7Prog{
		links:           map[string]link.Link{},
		l7EventsMapSize: conf.L7EventsBpfMapSize,
		trafficMapSize:  conf.TrafficBpfMapSize,
		logsMapsSize:    conf.LogsBpfMapSize,
	}
}

func (l7p *L7Prog) Close() {
	for hookName, link := range l7p.links {
		log.Logger.Info().Msgf("unattach %s", hookName)
		link.Close()
	}
}

func (l7p *L7Prog) Attach() {
	l, err := link.Tracepoint("syscalls", "sys_enter_read", c.BpfObjs.SysEnterRead, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_read tracepoint")
	}
	l7p.links["syscalls/sys_enter_read"] = l

	l1, err := link.Tracepoint("syscalls", "sys_enter_write", c.BpfObjs.SysEnterWrite, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_write tracepoint")
	}
	l7p.links["syscalls/sys_enter_write"] = l1

	l2, err := link.Tracepoint("syscalls", "sys_exit_read", c.BpfObjs.SysExitRead, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_read tracepoint")
	}
	l7p.links["syscalls/sys_exit_read"] = l2

	l3, err := link.Tracepoint("syscalls", "sys_enter_sendto", c.BpfObjs.SysEnterSendto, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_sendto tracepoint")
	}
	l7p.links["syscalls/sys_enter_sendto"] = l3

	l4, err := link.Tracepoint("syscalls", "sys_enter_recvfrom", c.BpfObjs.SysEnterRecvfrom, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_recvfrom tracepoint")
	}
	l7p.links["syscalls/sys_enter_recvfrom"] = l4

	l5, err := link.Tracepoint("syscalls", "sys_exit_recvfrom", c.BpfObjs.SysExitRecvfrom, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_recvfrom tracepoint")
	}
	l7p.links["syscalls/sys_exit_recvfrom"] = l5

	l6, err := link.Tracepoint("syscalls", "sys_exit_sendto", c.BpfObjs.SysExitSendto, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_sendto tracepoint")
	}
	l7p.links["syscalls/sys_exit_sendto"] = l6

	l7, err := link.Tracepoint("syscalls", "sys_exit_write", c.BpfObjs.SysExitWrite, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_write tracepoint")
	}
	l7p.links["syscalls/sys_exit_write"] = l7

	l8, err := link.Tracepoint("syscalls", "sys_enter_writev", c.BpfObjs.SysEnterWritev, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_enter_writev tracepoint")
	}
	l7p.links["syscalls/sys_enter_writev"] = l8

	l9, err := link.Tracepoint("syscalls", "sys_exit_writev", c.BpfObjs.SysExitWritev, nil)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("link sys_exit_writev tracepoint")
	}
	l7p.links["syscalls/sys_exit_writev"] = l9
}

func (l7p *L7Prog) InitMaps() {
	// initialize perf event readers
	var err error
	l7p.l7Events, err = perf.NewReader(c.BpfObjs.L7Events, int(l7p.l7EventsMapSize)*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	// read all bpf logs from the log map (note that all programs log to the same map)
	l7p.logs, err = perf.NewReader(c.BpfObjs.LogMap, int(l7p.logsMapsSize)*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf event array reader")
	}

	l7p.traffic, err = perf.NewReader(c.BpfObjs.IngressEgressCalls, int(l7p.trafficMapSize)*os.Getpagesize())
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("error creating perf reader")
	}
}

// returns when program is detached
func (l7p *L7Prog) Consume(ctx context.Context, ch chan interface{}) {
	stop := make(chan struct{})

	go func() {
		var logMessage []byte
		var funcName []byte
		read := func() {
			record, err := l7p.logs.Read()
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost #%d bpf logs", record.LostSamples)
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Warn().Msgf("read empty record from log perf array")
				return
			}

			logMsg := (*bpfLogMessage)(unsafe.Pointer(&record.RawSample[0]))

			funcEnd := findEndIndex(logMsg.FuncName)
			msgEnd := findEndIndex(logMsg.LogMsg)

			logMessage = logMsg.LogMsg[:msgEnd]
			funcName = logMsg.FuncName[:funcEnd]

			args := []struct {
				argName  string
				argValue uint64
			}{
				{
					argName:  "",
					argValue: 0,
				},
				{
					argName:  "",
					argValue: 0,
				},
				{
					argName:  "",
					argValue: 0,
				},
			}

			parseLogMessage := func(input []byte, logMsg *bpfLogMessage) []byte {
				// fd,x,y -- {log-msg}
				// fd,, -- {log-msg}

				parts := bytes.SplitN(input, []byte(" -- "), 2)
				if len(parts) != 2 {
					log.Logger.Warn().Msgf("invalid ebpf log message: %s", string(input))
					return nil
				}

				parsedArgs := bytes.SplitN(parts[1], []byte("|"), 3)
				if len(parsedArgs) != 3 {
					log.Logger.Warn().Msgf("invalid ebpf log message not 3 args: %s", string(input))
					return nil
				}

				args[0].argName = string(parsedArgs[0])
				args[0].argValue = logMsg.Arg1

				args[1].argName = string(parsedArgs[1])
				args[1].argValue = logMsg.Arg2

				args[2].argName = string(parsedArgs[2])
				args[2].argValue = logMsg.Arg3
				return parts[0]
			}

			// will change resultArgs
			logMessage = parseLogMessage(logMessage, logMsg)
			if logMessage == nil {
				log.Logger.Warn().Msgf("invalid ebpf log message: %s", string(logMsg.LogMsg[:]))
				return
			}

			switch logMsg.Level {
			case 0:
				log.Logger.Debug().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 1:
				log.Logger.Info().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 2:
				log.Logger.Warn().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			case 3:
				log.Logger.Error().Str("func", string(funcName)).Uint32("pid", logMsg.Pid).
					Uint64(args[0].argName, args[0].argValue).Uint64(args[1].argName, args[1].argValue).Uint64(args[2].argName, args[2].argValue).
					Str("log-msg", string(logMessage)).Msg("ebpf-log")
			}
		}
		for {
			select {
			case <-stop:
				return
			default:
				read()
			}
		}
	}()

	readKernelTime := &sync.Once{}
	go func() {
		var record perf.Record
		droppedCount := 0
		read := func() {
			err := l7p.l7Events.ReadInto(&record)
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from perf array")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost samples l7-event %d", record.LostSamples)
			}

			// TODO: investigate why this is happening
			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Warn().Msgf("read sample l7-event nil or empty")
				return
			}

			l7Event := (*bpfL7Event)(unsafe.Pointer(&record.RawSample[0]))

			// runs once
			readKernelTime.Do(func() {
				FirstUserspaceTime = uint64(time.Now().UnixNano())
				FirstKernelTime = l7Event.WriteTimeNs
			})

			protocol := L7ProtocolConversion(l7Event.Protocol).String()
			var method string
			switch protocol {
			case L7_PROTOCOL_HTTP:
				method = HTTPMethodConversion(l7Event.Method).String()
			case L7_PROTOCOL_AMQP:
				method = RabbitMQMethodConversion(l7Event.Method).String()
			case L7_PROTOCOL_POSTGRES:
				method = PostgresMethodConversion(l7Event.Method).String()
			case L7_PROTOCOL_HTTP2:
				method = Http2MethodConversion(l7Event.Method).String()
			case L7_PROTOCOL_REDIS:
				method = RedisMethodConversion(l7Event.Method).String()
			default:
				method = "Unknown"
			}

			// copy payload slice
			payload := [1024]uint8{}
			copy(payload[:], l7Event.Payload[:])

			userspacel7Event := &L7Event{
				Fd:                  l7Event.Fd,
				Pid:                 l7Event.Pid,
				Status:              l7Event.Status,
				Duration:            l7Event.Duration,
				Protocol:            protocol,
				Tls:                 uint8ToBool(l7Event.IsTls),
				Method:              method,
				Payload:             payload,
				PayloadSize:         l7Event.PayloadSize,
				PayloadReadComplete: uint8ToBool(l7Event.PayloadReadComplete),
				Failed:              uint8ToBool(l7Event.Failed),
				WriteTimeNs:         l7Event.WriteTimeNs,
				Tid:                 l7Event.Tid,
				Seq:                 l7Event.Seq,
			}

			go func(l7Event *L7Event) {
				select {
				case ch <- l7Event:
				default:
					droppedCount++
					if droppedCount%100 == 0 {
						log.Logger.Warn().
							Str("protocol", l7Event.Protocol).
							Str("method", l7Event.Method).
							Uint32("pid", l7Event.Pid).
							Uint32("status", l7Event.Status).
							Msg("channel full, dropping l7 event")
					}
				}
			}(userspacel7Event)
		}
		for {
			select {
			case <-stop:
				return
			default:
				read()
			}
		}
	}()

	go func() {
		var record perf.Record
		read := func() {
			err := l7p.traffic.ReadInto(&record)
			if err != nil {
				log.Logger.Warn().Err(err).Msg("error reading from dist trace calls")
			}

			if record.LostSamples != 0 {
				log.Logger.Warn().Msgf("lost samples dist-trace %d", record.LostSamples)
			}

			if record.RawSample == nil || len(record.RawSample) == 0 {
				log.Logger.Warn().Msgf("read sample dist-trace nil or empty")
				return
			}

			bpfTraceEvent := (*bpfTraceEvent)(unsafe.Pointer(&record.RawSample[0]))

			traceEvent := TraceEvent{
				Pid:   bpfTraceEvent.Pid,
				Tid:   bpfTraceEvent.Tid,
				Tx:    time.Now().UnixMilli(),
				Type_: bpfTraceEvent.Type_,
				Seq:   bpfTraceEvent.Seq,
			}
			ch <- &traceEvent

		}
		for {
			select {
			case <-stop:
				return
			default:
				read()
			}
		}
	}()

	<-ctx.Done() // wait for context to be cancelled
	close(stop)
	// defers will clean up
}

// 0 is false, 1 is true
func uint8ToBool(num uint8) bool {
	return num != 0
}

func findEndIndex(b [100]uint8) (endIndex int) {
	for i, v := range b {
		if v == 0 {
			return i
		}
	}
	return len(b)
}
