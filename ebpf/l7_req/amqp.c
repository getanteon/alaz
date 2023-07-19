// AMQP is a binary protocol. Information is organised into "frames", of various types. Frames carry
// protocol methods and other information. All frames have the same general format: 
// frame header, payload and frame end. The frame payload format depends on the frame type.

// Within a single socket connection, there can be multiple independent threads of control, called "channels".
// Each frame is numbered with a channel number. By interleaving their frames, different channels share the
// connection.

// The AMQP client and server negotiate the protocol.


// https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf
// 2.3.5 Frame Details

// All frames consist of a header (7 octets), a payload of arbitrary size, and a 'frame-end' octet that detects
// malformed frames


// Each frame in AMQP consists of a header, payload, and frame-end marker. 
// The header contains frame-specific information, such as the frame type, channel number, and payload size. 
// The payload field, in turn, holds the actual data associated with the frame.


// octet -> 1 byte

// FRAME FORMAT
// 0      1         3          7                   size+7 size+8
// +------+---------+--------- +-------------------+------+---------+
// | type | channel |  size    |  payload          | frame-end     |
// +------+---------+--------- +-------------------+------+---------+
// octet   short     long       size octets         octet
// --------header-------------

// FRAME PAYLOAD FORMAT FOR METHOD FRAMES
// 0          2          4
// +----------+----------+-----------+--------------+-------------+-------------+-------------+
// | class-id | method-id| arguments | class-id     | method-id   | arguments   | ...         |
// +----------+----------+-----------+--------------+-------------+-------------+-------------+
// short      short      ...         short          short         ...           ...


// Frame types and values
// 0x01: METHOD frame - Used to carry methods such as connection setup and channel operations.
// 0x02: HEADER frame - Used to carry content header properties for a message.
// 0x03: BODY frame - Used to carry message body content. (content frames)
// 0x04: HEARTBEAT frame - Used for keep-alive and monitoring purposes.



#define AMQP_FRAME_TYPE_METHOD 0x01
#define AMQP_FRAME_TYPE_HEADER 0x02
#define AMQP_FRAME_TYPE_CONTENT 0x03
#define AMQP_FRAME_TYPE_HEARTBEAT 0x04

#define AMQP_FRAME_END 0xCE

#define AMQP_CLASS_CONN 10 // handles connection-related operations, such as establishing and terminating connections, authentication, and handling connection parameters
#define AMQP_CLASS_CHANNEL 20 // including opening and closing channels, flow control, and channel-level exceptions
#define AMQP_CLASS_EXCHANGE 40 // for managing exchanges, which are entities that receive messages from producers and route them to queues based on certain criteria
#define AMQP_CLASS_QUEUE 50 // used for queue-related operations, such as declaring a queue, binding a queue to an exchange, and consuming a queue
#define AMQP_CLASS_BASIC 60 // used for basic message-related operations, such as publishing messages, consuming messages, and handling acknowledgments


// Methods differ according to the class they belong to

// Basic class methods
#define AMQP_METHOD_PUBLISH 40
#define AMQP_METHOD_CONSUME 60
#define AMQP_METHOD_ACK 80
#define AMQP_METHOD_REJECT 90


static __always_inline
int amqp_method_is(char *buf, __u64 buf_size, __u16 expected_method) {
    if (buf_size < 12) {
        return 0;
    }
    __u8 type = 0;
    bpf_probe_read(&type,sizeof(type),buf); // read the frame type
    if (type != AMQP_FRAME_TYPE_METHOD) {
        return 0;
    }

    __u32 size = 0;
    bpf_probe_read(&size,sizeof(size),buf+3); // read the frame size
    size = bpf_htonl(size);
    if (7 + size + 1 > buf_size) { // buf_size is smaller than the frame size
        return 0;
    }

    __u8 end = 0;
    bpf_probe_read(&end,sizeof(end),buf+7+size); // read the frame end, which is the last byte of the frame
    if (end != AMQP_FRAME_END) {
        return 0;
    }

    // the frame is a valid method frame
    // check the class and method from the frame payload

    __u16 class = 0;
    bpf_probe_read(&class,sizeof(class),buf+7);  // read the class-id
    if (bpf_htons(class) != AMQP_CLASS_BASIC) {
        return 0;
    }

    __u16 method = 0;
    bpf_probe_read(&method,sizeof(method),buf+9);
    if (bpf_htons(method) != expected_method) {
        return 0;
    }

    return 1;
}

static __always_inline
int is_rabbitmq_produce(char *buf, __u64 buf_size) {
    return amqp_method_is(buf, buf_size, AMQP_METHOD_PUBLISH);
}

static __always_inline
int is_rabbitmq_consume(char *buf, __u64 buf_size) {
    return amqp_method_is(buf, buf_size, AMQP_METHOD_CONSUME);
}
