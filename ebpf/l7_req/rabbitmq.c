// AMQP 0-9-1 Protocol Specification
// https://www.rabbitmq.com/protocol.html

#define RABBITMQ_FRAME_TYPE_METHOD 1
#define RABBITMQ_FRAME_END 0xCE

#define RABBITMQ_CLASS_BASIC 60
#define RABBITMQ_METHOD_PUBLISH 40
#define RABBITMQ_METHOD_DELIVER 60

#define METHOD_PRODUCE           1
#define METHOD_CONSUME           2


static __always_inline
int rabbitmq_method_is(char *buf, __u64 buf_size, __u16 expected_method) {
    if (buf_size < 12) {
        return 0;
    }
    __u8 type = 0;
    bpf_probe_read(&type,sizeof(type),buf);
    if (type != RABBITMQ_FRAME_TYPE_METHOD) {
        return 0;
    }

    __u32 size = 0;
    bpf_probe_read(&size,sizeof(size),buf+3);
    size = bpf_htonl(size);
    if (7 + size + 1 > buf_size) {
        return 0;
    }
    __u8 end = 0;
    bpf_probe_read(&end,sizeof(end),buf+7+size);
    if (end != RABBITMQ_FRAME_END) {
        return 0;
    }

    __u16 class = 0;
    bpf_probe_read(&class,sizeof(class),buf+7);
    if (bpf_htons(class) != RABBITMQ_CLASS_BASIC) {
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
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_PUBLISH);
}

static __always_inline
int is_rabbitmq_consume(char *buf, __u64 buf_size) {
    return rabbitmq_method_is(buf, buf_size, RABBITMQ_METHOD_DELIVER);
}
