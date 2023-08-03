// Postgres wire protocol
// https://www.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf
// https://www.postgresql.org/docs/current/protocol-message-formats.html

#define POSTGRES_FRAME_SIMPLE_QUERY 'Q'
#define POSTGRES_FRAME_PARSE 'P'
#define POSTGRES_FRAME_CLOSE 'C'

#define METHOD_UNKNOWN      0
#define METHOD_STATEMENT_CLOSE   1
#define METHOD_STATEMENT_PREPARE 2


static __always_inline
int is_postgres_query(char *buf, int buf_size, __u8 *request_type) {
    if (buf_size < 1) {
        return 0;
    }
    char f_cmd;
    int f_length;
    if (bpf_probe_read(&f_cmd, sizeof(f_cmd), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&f_length, sizeof(f_length), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    f_length = bpf_htonl(f_length);

    *request_type = f_cmd;
    if ((f_cmd == POSTGRES_FRAME_SIMPLE_QUERY || f_cmd == POSTGRES_FRAME_CLOSE) && f_length+1 == buf_size) {
        return 1;
    }
    char sync[5];
    if (bpf_probe_read(&sync, sizeof(sync), (void *)((char *)buf+buf_size-5)) < 0) {
        return 0;
    }
    if (sync[0] == 'S' && sync[1] == 0 && sync[2] == 0 && sync[3] == 0 && sync[4] == 4) {
        return 1;
    }
    return 0;
}

static __always_inline
__u32 parse_postgres_status(char *buf, int buf_size) {
    char cmd;
    int length;
    if (bpf_probe_read(&cmd, sizeof(cmd), (void *)((char *)buf)) < 0) {
        return 0;
    }
    if (bpf_probe_read(&length, sizeof(length), (void *)((char *)buf+1)) < 0) {
        return 0;
    }
    length = bpf_htonl(length);

    if (length+1 > buf_size) {
        return 0;
    }
    if ((cmd == '1' || cmd == '2') && length == 4 && buf_size >= 10) {
        if (bpf_probe_read(&cmd, sizeof(cmd), (void *)((char *)buf+5)) < 0) {
            return 0;
        }
        if (bpf_probe_read(&length, sizeof(length), (void *)((char *)buf+5+1)) < 0) {
            return 0;
        }
    }
    if (cmd == 'E') {
        return 500;
    }
    if (cmd == 't' || cmd == 'T' || cmd == 'D' || cmd == 'C') {
        return 200;
    }
    return 0;
}
