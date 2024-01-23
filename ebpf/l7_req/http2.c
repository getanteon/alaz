#define CLIENT_FRAME        1
#define SERVER_FRAME        2

#define MAGIC_MESSAGE_LEN 24

static __always_inline
int is_http2_magic(char *buf) {
    char buf_prefix[MAGIC_MESSAGE_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

   /*    
PRI * HTTP/2.0 
 
SM 
   */
    const char packet_bytes[MAGIC_MESSAGE_LEN] = {
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
        0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
        0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
    };

    for (int i = 0; i < MAGIC_MESSAGE_LEN; i++) {
        if (buf_prefix[i] != packet_bytes[i]) {
            return 0;
        }
    }

    return 1;
}

static __always_inline
int is_http2_magic_2(char *buf){
    char buf_prefix[MAGIC_MESSAGE_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;

    if (r < 0) {
        return 0;
    }


    if (buf_prefix[0] == 'P' && buf_prefix[1] == 'R' && buf_prefix[2] == 'I' && buf_prefix[3] == ' ' && buf_prefix[4] == '*' && buf_prefix[5] == ' ' && buf_prefix[6] == 'H' && buf_prefix[7] == 'T' && buf_prefix[8] == 'T' && buf_prefix[9] == 'P' && buf_prefix[10] == '/' && buf_prefix[11] == '2' && buf_prefix[12] == '.' && buf_prefix[13] == '0'){
        return 1;
    }
    return 0;
}


static __always_inline    
int is_http2_frame(char *buf, __u64 size) {
    if (size < 9) {
        return 0;
    }

    // magic message is not a frame 
    if (is_http2_magic_2(buf)){
        return 1;
    }
    
    // try to parse frame

    // 3 bytes length
    // 1 byte type
    // 1 byte flags
    // 4 bytes stream id
    // 9 bytes total

    // #length bytes payload

    __u32 length;
    bpf_read_into_from(length,buf);
    length = bpf_htonl(length) >> 8; // slide off the last 8 bits

    __u8 type;
    bpf_read_into_from(type,buf+3); // 3 bytes in
    
    // frame types are 1 byte
    // 0x00 DATA
    // 0x01 HEADERS
    // 0x02 PRIORITY
    // 0x03 RST_STREAM
    // 0x04 SETTINGS
    // 0x05 PUSH_PROMISE
    // 0x06 PING
    // 0x07 GOAWAY
    // 0x08 WINDOW_UPDATE
    // 0x09 CONTINUATION

    // other frames can precede headers frames, so only check if its a valid frame type
    if (type > 0x09){
        return 0;
    }

    __u32 stream_id; // 4 bytes
    bpf_read_into_from(stream_id,buf+5);
    stream_id = bpf_htonl(stream_id);

    // odd stream ids are client initiated
    // even stream ids are server initiated
    
    if (stream_id == 0) { // special stream for window updates, pings
        return 1;
    }
    
    // only track client initiated streams
    if (stream_id % 2 == 1) {
       return 1;
    }
    return 0;
}