// #include "http.c"
#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/l7_req.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define METHOD_UNKNOWN           0

#define MAX_PAYLOAD_SIZE 512

char __license[] SEC("license") = "Dual MIT/GPL";

// static __always_inline
// int is_http_request(const char *buf) {
//     char b[16];
//     if (bpf_probe_read_str(&b, sizeof(b), (const void *)buf) < 16) {
//         char msg[] = "could not read buffer\n";
//         bpf_trace_printk(msg, sizeof(msg));
//         return 0;
//     }
//     if (b[0] == 'G' && b[1] == 'E' && b[2] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'O' && b[2] == 'S' && b[3] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'H' && b[1] == 'E' && b[2] == 'A' && b[3] == 'D') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'U' && b[2] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'D' && b[1] == 'E' && b[2] == 'L' && b[3] == 'E' && b[4] == 'T' && b[5] == 'E') {
//         return 1;
//     }
//     if (b[0] == 'C' && b[1] == 'O' && b[2] == 'N' && b[3] == 'N' && b[4] == 'E' && b[5] == 'C' && b[6] == 'T') {
//         return 1;
//     }
//     if (b[0] == 'O' && b[1] == 'P' && b[2] == 'T' && b[3] == 'I' && b[4] == 'O' && b[5] == 'N' && b[6] == 'S') {
//         return 1;
//     }
//     if (b[0] == 'P' && b[1] == 'A' && b[2] == 'T' && b[3] == 'C' && b[4] == 'H') {
//         return 1;
//     }
    
//     char msg[] = "read buffer but not http\n";
//     bpf_trace_printk(msg, sizeof(msg));
//     return 0;
// }


struct l7_event {
    __u64 fd;
    // __u64 connection_timestamp;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");

struct rw_args_t {
    __u64 fd;
    char* buf;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(struct rw_args_t));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct socket_key {
    __u64 fd;
    __u32 pid;
    __s16 stream_id;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 partial;
    __u8 request_type;
    __s32 request_id;
    char payload[MAX_PAYLOAD_SIZE];
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(struct socket_key));
    __uint(value_size, sizeof(struct l7_request));
    __uint(max_entries, 32768);
} active_l7_requests SEC(".maps");

struct trace_event_raw_sys_exit_rw__stub {
    __u64 unused;
    long int id;
    long int ret;
};

struct iov {
    char* buf;
    __u64 size;
};

// static inline __attribute__((__always_inline__))
// int trace_enter_write(struct trace_event_raw_sys_enter_rw__stub* ctx,
//     __u64 fd, char *buf, __u64 size) {

//     __u64 id = bpf_get_current_pid_tgid();
//     // int zero = 0;

//     struct l7_request req = {};

//     (&req)->protocol = PROTOCOL_UNKNOWN;
//     (&req)->partial = 0;
//     (&req)->request_id = 0;
//     (&req)->write_time_ns = 0;
    
//     struct socket_key k = {};
//     k.pid = id >> 32;
//     k.fd = fd;
//     k.stream_id = -1;

//     if (is_http_request(buf)) {
//         (&req)->protocol = PROTOCOL_HTTP;
//     } else {
//         // TODO: support other protocols
//         return 0;
//     }

//     if ((&req)->write_time_ns == 0) {
//         (&req)->write_time_ns = bpf_ktime_get_ns();
//     }
    
    

//     bpf_probe_read((&req)->payload, MAX_PAYLOAD_SIZE, (void *)buf);
//     bpf_map_update_elem(&active_l7_requests, &k, (&req), BPF_ANY);
//     return 0;
// }

// static inline __attribute__((__always_inline__))
// int trace_exit_read(struct trace_event_raw_sys_exit_rw__stub* ctx) {

//     __u64 id = bpf_get_current_pid_tgid();
//     int zero = 0;
//     struct rw_args_t *args = bpf_map_lookup_elem(&active_reads, &id);
//     if (!args) {
//         return 0;
//     }
    
//     struct socket_key k = {};
//     k.pid = id >> 32;
//     k.fd = args->fd;
//     k.stream_id = -1;
//     char *buf = args->buf;
//     __u64 size = args->size;

//     bpf_map_delete_elem(&active_reads, &id);

//     if (ctx->ret <= 0) {
//         return 0;
//     }

//     struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
//     if (!e) {
//         return 0;
//     }
//     e->fd = k.fd;
//     e->pid = k.pid;
//     e->connection_timestamp = 0;
//     e->status = 0;
//     e->method = METHOD_UNKNOWN;
//     e->statement_id = 0;

//     if (is_rabbitmq_consume(buf, size)) {
//         e->protocol = PROTOCOL_RABBITMQ;
//         e->status = 200;
//         e->method = METHOD_CONSUME;
//         bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
//         return 0;
//     }

//     struct cassandra_header cassandra_response = {};
//     cassandra_response.stream_id = -1;
//     struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
//     if (!req) {
//         if (bpf_probe_read(&cassandra_response, sizeof(cassandra_response), (void *)(buf)) < 0) {
//             return 0;
//         }
//         k.stream_id = cassandra_response.stream_id;
//         req = bpf_map_lookup_elem(&active_l7_requests, &k);
//         if (!req) {
//             return 0;
//         }
//     }

//     bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);
//     __s32 request_id = req->request_id;
//     e->protocol = req->protocol;
//     __u64 ns = req->ns;
//     __u8 partial = req->partial;
//     __u8 request_type = req->request_type;
//     bpf_map_delete_elem(&active_l7_requests, &k);
//     if (e->protocol == PROTOCOL_HTTP) {
//         e->status = parse_http_status(buf);
//     } else if (e->protocol == PROTOCOL_POSTGRES) {
//         e->status = parse_postgres_status(buf, ctx->ret);
//         if (request_type == POSTGRES_FRAME_PARSE) {
//             e->method = METHOD_STATEMENT_PREPARE;
//         }
//     } else if (e->protocol == PROTOCOL_REDIS) {
//         e->status = parse_redis_status(buf, ctx->ret);
//     } else if (e->protocol == PROTOCOL_MEMCACHED) {
//         e->status = parse_memcached_status(buf, ctx->ret);
//     } else if (e->protocol == PROTOCOL_MYSQL) {
//         e->status = parse_mysql_response(buf, ctx->ret, request_type, &e->statement_id);
//         if (request_type == MYSQL_COM_STMT_PREPARE) {
//             e->method = METHOD_STATEMENT_PREPARE;
//         }
//     } else if (e->protocol == PROTOCOL_MONGO) {
//         e->status = parse_mongo_status(buf, ctx->ret, partial);
//         if (e->status == 1) {
//             struct l7_request *r = bpf_map_lookup_elem(&l7_request_heap, &zero);
//             if (!r) {
//                 return 0;
//             }
//             r->partial = 1;
//             r->protocol = e->protocol;
//             r->ns = ns;
//             bpf_probe_read(r->payload, MAX_PAYLOAD_SIZE, e->payload);
//             bpf_map_update_elem(&active_l7_requests, &k, r, BPF_ANY);
//             return 0;
//         }
//     } else if (e->protocol == PROTOCOL_KAFKA) {
//         e->status = parse_kafka_status(request_id, buf, ctx->ret, partial);
//     } else if (e->protocol == PROTOCOL_CASSANDRA) {
//         e->status = cassandra_status(cassandra_response);
//     }

//     if (e->status == 0) {
//         return 0;
//     }
//     e->duration = bpf_ktime_get_ns() - ns;
//     bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
//     return 0;
// }


// enter_write is used for write, writev, sendto, sendmsg

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_write* ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    // this way req is allocated on the stack
    // struct l7_request req = {};

    // moving the large variables into a BPF per-CPU array map, you ensure that the data is stored in a memory area that is not subject to the stack limit
    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);

    if (!req) {
        char msg[] = "Err: Could not get request from l7_request_heap";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }

    req->protocol = PROTOCOL_UNKNOWN;
    req->partial = 0;
    req->request_id = 0; // TODO: request_id
    req->write_time_ns = 0;
    // // TODO: request_type is not used
    
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = ctx->fd;
    k.stream_id = -1;

    if(ctx->buf){
        char b[16];
        long r = bpf_probe_read(&b, sizeof(b), (void *)(ctx->buf)) ;
        
        if (r < 0) {
            char msg[] = "could not read into buffer - %ld";
            bpf_trace_printk(msg, sizeof(msg), r);
            return 0;
        }

        // TODO: get all types of http requests
        if (!(b[0] == 'G' && b[1] == 'E' && b[2] == 'T')) {
            return 0; // TODO: only allow GET requests for now
        }else{
            char msg[] = "GET request";
            bpf_trace_printk(msg, sizeof(msg));
        }
        
    }else{
        char msgCtx[] = "ctxbuf null";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        return 0;
    }

    if (req->write_time_ns == 0) {
        req->write_time_ns = bpf_ktime_get_ns();
    }

    bpf_probe_read(req->payload, MAX_PAYLOAD_SIZE, (const void *)ctx->buf);
    
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if(res < 0)
    {
		char msg[] = "Error writing to active_l7_requests - %ld";
		bpf_trace_printk(msg, sizeof(msg), res);
    }else
    {
        char msgSuccess[] = "success active_l7_requests";
        bpf_trace_printk(msgSuccess, sizeof(msgSuccess));        
    }

    return 0;
}



// // multiple buffers
// SEC("tracepoint/syscalls/sys_enter_writev")
// int sys_enter_writev(struct trace_event_raw_sys_enter_rw__stub* ctx) {
//     struct iov iov0 = {};
//     if (bpf_probe_read(&iov0, sizeof(struct iov), (void *)ctx->buf) < 0) {
//         return 0;
//     }
//     return trace_enter_write(ctx, ctx->fd, iov0.buf, iov0.size);
// }

// // connectionless write
// SEC("tracepoint/syscalls/sys_enter_sendto")
// int sys_enter_sendto(struct trace_event_raw_sys_enter_rw__stub* ctx) {
//     return trace_enter_write(ctx, ctx->fd, ctx->buf, ctx->size);
// }

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_read* ctx) {
     __u64 id = bpf_get_current_pid_tgid();
    struct rw_args_t args = {};
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    args.size = ctx->count;
    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

// SEC("tracepoint/syscalls/sys_enter_readv")
// int sys_enter_readv(struct trace_event_raw_sys_enter_rw__stub* ctx) {
//     __u64 id = bpf_get_current_pid_tgid();
//     void *vec;
//     if (bpf_probe_read(&vec, sizeof(void*), (void *)ctx->buf) < 0) {
//         return 0;
//     }
//     struct rw_args_t args = {};
//     args.fd = ctx->fd;
//     args.buf = vec;
//     bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
//     return 0;
// }

// SEC("tracepoint/syscalls/sys_enter_recvfrom")
// int sys_enter_recvfrom(struct trace_event_raw_sys_enter_rw__stub* ctx) {
//     return trace_enter_read(ctx);
// }

// SEC("tracepoint/syscalls/sys_exit_read")
// int sys_exit_read(struct trace_event_raw_sys_exit_rw__stub* ctx) {
//     __u64 id = bpf_get_current_pid_tgid();
//     struct rw_args_t *args = bpf_map_lookup_elem(&active_reads, &id);
//     if (!args) {
//         return 0;
//     }
    
//     struct socket_key k = {};
//     k.pid = id >> 32;
//     k.fd = args->fd;
//     k.stream_id = -1;

//     // read buffer from socket 
//     char *buf = args->buf;
//     // __u64 size = args->size;

//     bpf_map_delete_elem(&active_reads, &id);

//     if (ctx->ret <= 0) { // TODO: error ? understand
//         return 0;
//     }

//     // TODO: l7_request_heap ?
//     int zero = 0;
//     struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
//     if (!e) {
//         return 0;
//     }


//     e->fd = k.fd;
//     e->pid = k.pid;
//     // e->connection_timestamp = 0;
//     e->status = 0;
//     e->method = METHOD_UNKNOWN;

//     struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
//     if (!req) {
//         return 0;
//     }

//     // copy req payload
//     bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);

//     // __s32 request_id = req->request_id;
//     e->protocol = req->protocol;
//     __u64 write_time_in_ns = req->write_time_ns;
//     // __u8 partial = req->partial;
//     // __u8 request_type = req->request_type;
//     bpf_map_delete_elem(&active_l7_requests, &k);
    
    
//     if (e->protocol == PROTOCOL_HTTP) {
//         e->status = parse_http_status(buf);
//     } 
   
//     if (e->status == 0) {
//         return 0;
//     }
    
//     e->duration = bpf_ktime_get_ns() - write_time_in_ns;
//     bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
//     return 0;
// }


// SEC("tracepoint/syscalls/sys_exit_readv")
// int sys_exit_readv(struct trace_event_raw_sys_exit* ctx) {
//     ctx->id = bpf_get_current_pid_tgid();
//     return trace_exit_read(ctx);
// }

// SEC("tracepoint/syscalls/sys_exit_recvfrom")
// int sys_exit_recvfrom(struct trace_event_raw_sys_exit_rw__stub* ctx) {
//     return trace_exit_read(ctx);
// }
