//go:build ignore
// https://kafka.apache.org/protocol.html

// RequestOrResponse => Size (RequestMessage | ResponseMessage)
//   Size => int32


// Request Header v0 => request_api_key request_api_version correlation_id 
//   request_api_key => INT16
//   request_api_version => INT16
//   correlation_id => INT32
//   client_id => NULLABLE_STRING // added in v1

// method will be decoded in user space
// #define METHOD_KAFKA_PRODUCE 1

struct kafka_request_header {
    __s32 size;
    __s16 api_key;
    __s16 api_version;
    __s32 correlation_id;
};

// Response Header v1 => correlation_id TAG_BUFFER 
//   correlation_id => INT32

struct kafka_response_header {
    __s32 size;
    __s32 correlation_id;
};

static __always_inline
int is_kafka_request_header(char *buf, __u64 buf_size, __s32 *request_id) {
    struct kafka_request_header h = {};
    if (buf_size < sizeof(h)) {
        return 0;
    }

    if (bpf_probe_read(&h, sizeof(h), buf) < 0) { 
        return 0;                                     
    }           

    h.size = bpf_htonl(h.size);
    
    // we parse only one message in one write syscall for now.
    // batch publish is not supported.
    if (h.size+4 != buf_size) {
        return 0;
    }

    h.api_key = bpf_htons(h.api_key); // determines message api, ProduceAPI, FetchAPI, etc.
//    h.api_version = bpf_htons(h.api_version); // version of the API, v8, v9, etc.
    h.correlation_id = bpf_htonl(h.correlation_id);
    if (h.correlation_id > 0 && (h.api_key >= 0 && h.api_key <= 74)) { // https://kafka.apache.org/protocol.html#protocol_api_keys
        *request_id = h.correlation_id;
        return 1;
    }
    return 0;
}

static __always_inline
int is_kafka_response_header(char *buf, __s32 correlation_id) {
    struct kafka_response_header h = {};
    if (bpf_probe_read(&h, sizeof(h), buf) < 0) { 
        return 0;                                     
    }    
    // correlation_id match
    if (bpf_htonl(h.correlation_id) == correlation_id) {
        return 1;
    }
    return 0;
}


