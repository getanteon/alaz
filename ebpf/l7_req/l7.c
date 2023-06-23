// #include "http.c"
#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/l7_req.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define METHOD_UNKNOWN      0

#define MAX_PAYLOAD_SIZE 512

char __license[] SEC("license") = "Dual MIT/GPL";

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

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 partial;
    __u8 request_type;
    __s32 request_id;
    char payload[MAX_PAYLOAD_SIZE];
};

// Instead of allocating on bpf stack, we allocate on a per-CPU array map
struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_event);
     __uint(max_entries, 1);
} l7_event_heap SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} l7_request_heap SEC(".maps");

// send l7 events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} l7_events SEC(".maps");


// when given with __type macro below
// type *btf.Pointer not supported
struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

struct socket_key {
    __u64 fd;
    __u32 pid;
    __s16 stream_id;
};


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");



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

            // normally print after write to map
            char msgCtx[] = "socket_key on write pid %d fd %d";
            bpf_trace_printk(msgCtx, sizeof(msgCtx), k.pid, k.fd);
        }
    }else{
        char msgCtx[] = "ctxbuf null";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        return 0;
    }

    if (req->write_time_ns == 0) {
        req->write_time_ns = bpf_ktime_get_ns();
    }

    // TODO: core
    bpf_probe_read(req->payload, MAX_PAYLOAD_SIZE, (const void *)ctx->buf);
    
    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if(res < 0)
    {
		char msg[] = "Error writing to active_l7_requests - %ld";
		bpf_trace_printk(msg, sizeof(msg), res);
    }

    return 0;
}


SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_read* ctx) {
     __u64 id = bpf_get_current_pid_tgid();
    struct read_args args = {};
    //
    args.fd = ctx->fd;
    args.buf = ctx->buf;
    args.size = ctx->count;

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = ctx->fd;
    k.stream_id = -1;

    // assume process is reading from the same socket it wrote to
    void* res = bpf_map_lookup_elem(&active_l7_requests, &k);
    if(!res) // if not found
    {
        char msgCtx[] = "sys_enter_read/ could not find on active_l7_requests pid %d fd %d";
        bpf_trace_printk(msgCtx, sizeof(msgCtx), k.pid, k.fd);
        return 0;
    }

    bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_read* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &id);
    if (!args) {
        return 0;
    }

    // char msgCtx[] = "sys_exit_read pid %d fd %d";
    // bpf_trace_printk(msgCtx, sizeof(msgCtx), id >> 32, args->fd);
    
    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = args->fd; // 0
    k.stream_id = -1;

 
    // TODO: get status from buffer
    // char *buf = args->buf;
    // __u64 size = args->size;

    bpf_map_delete_elem(&active_reads, &id);

    if (ctx->ret <= 0) { // TODO: error ? understand
        return 0;
    }

    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        return 0;
    }

    e->fd = k.fd;
    e->pid = k.pid;
    // e->connection_timestamp = 0;
    e->status = 0;
    e->method = METHOD_UNKNOWN;

    char msgCtx22[] = "trying to lookup active_l7_requests %d fd %d";
    bpf_trace_printk(msgCtx22, sizeof(msgCtx22), k.pid, k.fd);

    struct l7_request *req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!req) {
        return 0;
    }

    char msgCtx5[] = "socket_key on successfull lookup pid %d fd %d";
    bpf_trace_printk(msgCtx5, sizeof(msgCtx5), k.pid, k.fd);

    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);

    // __s32 request_id = req->request_id;
    e->protocol = req->protocol;
    e->duration = bpf_ktime_get_ns() - req->write_time_ns; // TODO: debug duration

    // __u8 partial = req->partial;
    // __u8 request_type = req->request_type;
    bpf_map_delete_elem(&active_l7_requests, &k);
    
    
    // if (e->protocol == PROTOCOL_HTTP) {
    //     e->status = parse_http_status(buf);
    // } 
   
    // TODO: protocol check, parse http_status
    
    bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}


// SEC("tracepoint/syscalls/sys_exit_readv")
// int sys_exit_readv(struct trace_event_raw_sys_exit* ctx) {
//     ctx->id = bpf_get_current_pid_tgid();
//     return trace_exit_read(ctx);
// }

// SEC("tracepoint/syscalls/sys_exit_recvfrom")
// int sys_exit_recvfrom(struct trace_event_raw_sys_exit_rw__stub* ctx) {
//     return trace_exit_read(ctx);
// }
