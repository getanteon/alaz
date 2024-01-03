#define METHOD_UNKNOWN      0
#define METHOD_GET          1
#define METHOD_POST         2
#define METHOD_PUT          3
#define METHOD_PATCH        4
#define METHOD_DELETE       5
#define METHOD_HEAD         6
#define METHOD_CONNECT      7
#define METHOD_OPTIONS      8
#define METHOD_TRACE        9

#define MIN_METHOD_LEN      8
#define MIN_RESP_LEN        12

static __always_inline
int parse_http_method(char *buf) {
    char buf_prefix[MIN_METHOD_LEN];
    long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

    if (buf_prefix[0] == 'G' && buf_prefix[1] == 'E' && buf_prefix[2] == 'T') {
            return METHOD_GET;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'O' && buf_prefix[2] == 'S' && buf_prefix[3] == 'T'){
        return METHOD_POST;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'U' && buf_prefix[2] == 'T'){
        return METHOD_PUT;
    }else if(buf_prefix[0] == 'P' && buf_prefix[1] == 'A' && buf_prefix[2] == 'T' && buf_prefix[3] == 'C' && buf_prefix[4] == 'H'){
        return METHOD_PATCH;
    }else if(buf_prefix[0] == 'D' && buf_prefix[1] == 'E' && buf_prefix[2] == 'L' && buf_prefix[3] == 'E' && buf_prefix[4] == 'T' && buf_prefix[5] == 'E'){
        return METHOD_DELETE;
    }else if(buf_prefix[0] == 'H' && buf_prefix[1] == 'E' && buf_prefix[2] == 'A' && buf_prefix[3] == 'D'){
        return METHOD_HEAD;
    }else if (buf_prefix[0] == 'C' && buf_prefix[1] == 'O' && buf_prefix[2] == 'N' && buf_prefix[3] == 'N' && buf_prefix[4] == 'E' && buf_prefix[5] == 'C' && buf_prefix[6] == 'T'){
        return METHOD_CONNECT;
    }else if(buf_prefix[0] == 'O' && buf_prefix[1] == 'P' && buf_prefix[2] == 'T' && buf_prefix[3] == 'I' && buf_prefix[4] == 'O' && buf_prefix[5] == 'N' && buf_prefix[6] == 'S'){
        return METHOD_OPTIONS;
    }else if(buf_prefix[0] == 'T' && buf_prefix[1] == 'R' && buf_prefix[2] == 'A' && buf_prefix[3] == 'C' && buf_prefix[4] == 'E'){
        return METHOD_TRACE;
    }
    return -1;
}

static __always_inline
int parse_http_status(char *buf) {

    char b[MIN_RESP_LEN];
    long r = bpf_probe_read(&b, sizeof(b), (void *)(buf)) ;
    
    if (r < 0) {
        return 0;
    }

    // HTTP/1.1 200 OK
    if (b[0] != 'H' || b[1] != 'T' || b[2] != 'T' || b[3] != 'P' || b[4] != '/') {
        return -1;
    }
    if (b[5] < '0' || b[5] > '9') {
        return -1;
    }
    if (b[6] != '.') {
        return -1;
    }
    if (b[7] < '0' || b[7] > '9') {
        return -1;
    }
    if (b[8] != ' ') {
        return -1;
    }
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9') {
        return -1;
    }
    return (b[9]-'0')*100 + (b[10]-'0')*10 + (b[11]-'0');
}
