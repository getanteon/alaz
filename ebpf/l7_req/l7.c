#include "../headers/bpf.h"
#include "../headers/common.h"
#include "../headers/l7_req.h"

// order is important
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <stddef.h>
#include "../headers/pt_regs.h"

#include "http.c"
#include "amqp.c"
#include "postgres.c"
#include "openssl.c"

#define PROTOCOL_UNKNOWN    0
#define PROTOCOL_HTTP	    1
#define PROTOCOL_AMQP	2
#define PROTOCOL_POSTGRES	3

#define MAX_PAYLOAD_SIZE 512
#define PAYLOAD_PREFIX_SIZE 16

// for rabbitmq methods
#define METHOD_PUBLISH           1
#define METHOD_DELIVER           2


#define TLS_MASK 0x8000000000000000

char __license[] SEC("license") = "Dual MIT/GPL";

struct l7_event {
    __u64 fd;
    __u64 write_time_ns;
    __u32 pid;
    __u32 status;
    __u64 duration;
    __u8 protocol;
    __u8 method;
    __u16 padding;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 failed;
    __u8 is_tls;
};

struct l7_request {
    __u64 write_time_ns;  
    __u8 protocol;
    __u8 method;
    unsigned char payload[MAX_PAYLOAD_SIZE];
    __u32 payload_size;
    __u8 payload_read_complete;
    __u8 request_type;
};

struct socket_key {
    __u64 fd;
    __u32 pid;
    __u8 is_tls;
};

struct go_req_key {
    __u32 pid;
    __u64 fd;
};

struct go_read_key {
    __u32 pid;
    __u64 goid; // goroutine id
    // __u64 fd; can't have fd at exit of read, because it is not available
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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct socket_key);
    __type(value, struct l7_request);
} active_l7_requests SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct l7_request);
     __uint(max_entries, 1);
} go_l7_request_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct go_req_key);
    __type(value, struct l7_request);
} go_active_l7_requests SEC(".maps");

struct go_read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct go_read_key);
    __uint(value_size, sizeof(struct go_read_args));
    __uint(max_entries, 10240);
} go_active_reads SEC(".maps");

// send l7 events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 10240);
} l7_events SEC(".maps");

// when given with __type macro below
// type *btf.Pointer not supported
struct read_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 read_start_ns;  
};

// used for cases in which we don't have a read event
// we are only tracking write events.
// so we need to know when a write event is complete
// so we can send the l7 event to userspace
struct write_args {
    __u64 fd;
    char* buf;
    __u64 size;
    __u64 write_start_ns;  
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct read_args));
    __uint(max_entries, 10240);
} active_reads SEC(".maps");

// used for cases in which we only use write events
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64); // pid_tgid
    __uint(value_size, sizeof(struct write_args));
    __uint(max_entries, 10240);
} active_writes SEC(".maps");

// Processing enter of write and sendto syscalls
static __always_inline
int process_enter_of_syscalls_write_sendto(void* ctx, __u64 fd, __u8 is_tls, char* buf, __u64 count){
    __u64 id = bpf_get_current_pid_tgid();

    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&l7_request_heap, &zero);

    if (!req) {
        char msg[] = "Err: Could not get request from l7_request_heap";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }

    req->protocol = PROTOCOL_UNKNOWN;
    req->method = METHOD_UNKNOWN;
    req->request_type = 0;
    req->write_time_ns = bpf_ktime_get_ns();

    // TODO: If socket is not tcp (SOCK_STREAM), we are not interested in it

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = fd;
    k.is_tls = is_tls;

    

    if(buf){
        // We are tracking tcp connections (sockets) on tcp_state bpf program, sending them to userspace
        // and then we are tracking http requests on this bpf program, sending them to userspace

        // We should not send l7_events that is not related to a tcp connection,
        // otherwise we will have a lot of events that are not related to a tcp connection
        // and we will not be able to match them with a tcp connection.
        // Also, file descriptors are reused, so tcp and udp sockets can have the same fd at different times.
        // This can cause mismatched events. (udp request with tcp connection)
        // Userspace only knows about tcp connections, so we should only send l7_events that are related to a tcp connection. 

        int method = parse_http_method(buf);
        if (method != -1){
            req->protocol = PROTOCOL_HTTP;
            req-> method = method;
        }else if (is_rabbitmq_publish(buf,count)){
            req->protocol = PROTOCOL_AMQP;
            req->method = METHOD_PUBLISH;
            struct write_args args = {};
            args.fd = fd;
            args.write_start_ns = bpf_ktime_get_ns();
            bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
        }else if (parse_client_postgres_data(buf, count, &req->request_type)){
            // TODO: should wait for CloseComplete message in case of statement close 
            if (req->request_type == POSTGRES_MESSAGE_CLOSE || req->request_type == POSTGRES_MESSAGE_TERMINATE){
                req->protocol = PROTOCOL_POSTGRES;
                req->method = METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE;
                struct write_args args = {};
                args.fd = fd;
                args.write_start_ns = bpf_ktime_get_ns();
                bpf_map_update_elem(&active_writes, &id, &args, BPF_ANY);
            }
            req->protocol = PROTOCOL_POSTGRES;
        }else{
            req->protocol = PROTOCOL_UNKNOWN;
            req->method = METHOD_UNKNOWN;
            return 0; // do not continue processing for now (udp requests are flowing and overlaps with http requests)
        }
    }else{
        char msgCtx[] = "write buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        return 0;
    }

    bpf_probe_read(&req->payload, sizeof(req->payload), (const void *)buf);
    if(count > MAX_PAYLOAD_SIZE){
        // will not be able to copy all of it
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    }else{
        req->payload_size = count;
        req->payload_read_complete = 1;
    }

    long res = bpf_map_update_elem(&active_l7_requests, &k, req, BPF_ANY);
    if(res < 0)
    {
		char msg[] = "Error writing to active_l7_requests - %ld";
		bpf_trace_printk(msg, sizeof(msg), res);
    }

    return 0;
}


// Processing enter of read, recv, recvfrom syscalls
static __always_inline
int process_enter_of_syscalls_read_recvfrom(__u64 id, __u32 pid, __u64 fd, char* buf, __u64 size) {
    // __u64 id = bpf_get_current_pid_tgid();
    
    // struct socket_key k = {};
    // k.pid = pid;
    // k.fd = fd;

    // since a message consume in amqp does not have a prior write, we will not have a request in active_l7_requests
    // only in http, a prior write is needed, so we will have a request in active_l7_requests

    // void* active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    // if(!active_req) // if not found
    // {
    //     return 0;
    // }

    
    struct read_args args = {};
    args.fd = fd;
    args.buf = buf;
    args.size = size;
    args.read_start_ns = bpf_ktime_get_ns();

    long res = bpf_map_update_elem(&active_reads, &id, &args, BPF_ANY);
    if(res < 0)
    {
        char msg[] = "Error writing to active_reads - %ld";
        bpf_trace_printk(msg, sizeof(msg), res);
    }
    return 0;
}


static __always_inline
int process_exit_of_syscalls_write_sendto(void* ctx, __s64 ret){
    __u64 id = bpf_get_current_pid_tgid();

    // we only used this func for amqp, others will only be in active_l7_requests
    // used active_writes for cases that only depends on writes, like amqp publish
    // + postgres statement close, terminate
    struct write_args *active_write = bpf_map_lookup_elem(&active_writes, &id);
    if (!active_write) {
        bpf_map_delete_elem(&active_writes, &id);
        return 0;
    }

    struct socket_key k = {};
    k.pid = id >> 32;
    k.fd = active_write->fd;

    // active_l7_requests 
    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if(!active_req) // if not found
    {
        return 0;
    }

    // write success
    if(ret>=0){
        // send l7 event
        int zero = 0;
        struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
        if (!e) {
            bpf_map_delete_elem(&active_writes, &id);
            return 0;
        }

        e->protocol = active_req->protocol;
        e->fd = k.fd;
        e->pid = k.pid;
        e->method = active_req->method;
        if (e->protocol == PROTOCOL_POSTGRES && e->method == METHOD_STATEMENT_CLOSE_OR_CONN_TERMINATE){
            e->status = 1; // success
        }else{
            e->status = 0;
        }

        e->failed = 0; // success
        e->duration = bpf_ktime_get_ns()- active_write->write_start_ns; // total write time

        // request payload
        e->payload_size = active_req->payload_size;
        e->payload_read_complete = active_req->payload_read_complete;
        e->is_tls = 0;
        
        // copy req payload
        bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

        bpf_map_delete_elem(&active_l7_requests, &k);
        bpf_map_delete_elem(&active_writes, &id);

        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    }else{
        // write failed
        bpf_map_delete_elem(&active_writes, &id);
        bpf_map_delete_elem(&active_l7_requests, &k);
    }
    return 0;
}

static __always_inline
int process_exit_of_syscalls_read_recvfrom(void* ctx, __u64 id, __u32 pid, __s64 ret, __u8 is_tls) {
    if (ret < 0) { // read failed
        // -ERRNO
        // __u64 id = bpf_get_current_pid_tgid();

        // check if this read was initiated by us
        struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
        if (!read_info) {
            return 0;
        }

        struct socket_key k = {};
        k.pid = pid;
        k.fd = read_info->fd;
        k.is_tls = is_tls;

        // clean up
        bpf_map_delete_elem(&active_reads, &id);

        // bpf_map_delete_elem(&active_l7_requests, &k);
        // TODO: Before we were cleaning the record active_l7_requests in case of a failed read
        // in order to avoid filling up the map with requests that will never be sent to userspace in case of consecutive failed read attempts(request failure actually, could not read the response).
        // But if the first read fails and we delete the record from active_l7_requests, 
        // we will not be able to send the l7 event in case of a retried first read call succeeds.
        
        // TODO: On roadmap, when we want to parse the whole response, we have to send all chunks to userspace in order to parse the whole response.
        // Right now, we only cover the case that we read the first 16 bytes of first successful read call of response, trying to parse the status code

        return 0;
    }


    // __u64 id = bpf_get_current_pid_tgid();
    struct read_args *read_info = bpf_map_lookup_elem(&active_reads, &id);
    if (!read_info) {
        if (is_tls){
            char msg[] = "tls could not find read_info";
            bpf_trace_printk(msg, sizeof(msg));
        }
        return 0;
    }
    
    struct socket_key k = {};
    k.pid = pid;
    k.fd = read_info->fd; 
    k.is_tls = is_tls;

    // Instead of allocating on bpf stack, use cpu map
    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
    e->is_tls = is_tls;

    // For a amqp consume, there will be no write, so we will not have a request in active_l7_requests
    // Process amqp consume first, if it is not amqp consume, look for a request in active_l7_requests

    if (is_rabbitmq_consume(read_info->buf, ret)) {
        e->protocol = PROTOCOL_AMQP;
        e->method = METHOD_DELIVER;
    e->duration = bpf_ktime_get_ns()- read_info->read_start_ns;
        e->write_time_ns = read_info->read_start_ns; // TODO: it is not write time, but start of read time
        e->payload_size = 0;
        e->payload_read_complete = 0;
        e->failed = 0; // success
        e->status = 0;
        e->fd = k.fd;
        e->pid = k.pid;
        
        // reset payload
        for (int i = 0; i < MAX_PAYLOAD_SIZE; i++) {
            e->payload[i] = 0;
        }
        
        bpf_map_delete_elem(&active_reads, &id);
        bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
        return 0;
    }

    struct l7_request *active_req = bpf_map_lookup_elem(&active_l7_requests, &k);
    if (!active_req) {
        if (is_tls){
            char msg[] = "tls could not find active_l7_req fd: %ld, pid: %ld";
            bpf_trace_printk(msg, sizeof(msg), k.fd, k.pid);
        }
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }

    e->fd = k.fd;
    e->pid = k.pid;

    e->method = active_req->method;

    e->protocol = active_req->protocol;
    e->duration = bpf_ktime_get_ns() - active_req->write_time_ns;
    
    e->write_time_ns = active_req->write_time_ns;
    
    // request payload
    e->payload_size = active_req->payload_size;
    e->payload_read_complete = active_req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, active_req->payload);

    e->failed = 0; // success

    e->status = 0;
    if(read_info->buf && ret > PAYLOAD_PREFIX_SIZE){
        if(e->protocol==PROTOCOL_HTTP){ // if http, try to parse status code
            // read first 16 bytes of read buffer
            char buf_prefix[PAYLOAD_PREFIX_SIZE];
            long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(read_info->buf)) ;
            
            if (r < 0) {
                char msg[] = "could not read into buf_prefix - %ld";
                bpf_trace_printk(msg, sizeof(msg), r);
                bpf_map_delete_elem(&active_reads, &id);
                return 0;
            }

            int status = parse_http_status(buf_prefix);
            if (status != -1){
                e->status = status;
            }else{
                // status code will be send as 0 if not returned
                // In case of write happens but read_exit probe doesn't get called for a request (sigkill of process?)
                // a read from the same socket (same pid-fd pair) after some time, can match with the previous write
                // if the latter is http1.1, requests can mismatch (if expression above will satisfy)
                // or(not http1.1) the status code will be 0 if continued processing.
                // So we'll clean up the request here if it's not a protocol we support before hand.
                // mismatches can still occur, but it's better than nothing.
                // TODO: find a solution for the mismatch problem

                bpf_map_delete_elem(&active_reads, &id);
                return 0;
            }
        }else if (e->protocol == PROTOCOL_POSTGRES){
            e->status = parse_postgres_server_resp(read_info->buf, ret);
            if (active_req->request_type == POSTGRES_MESSAGE_SIMPLE_QUERY) {
                e->method = METHOD_SIMPLE_QUERY;
            }
        }
    }else{
        char msgCtx[] = "read buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        bpf_map_delete_elem(&active_reads, &id);
        return 0;
    }
       
    bpf_map_delete_elem(&active_reads, &id);
    bpf_map_delete_elem(&active_l7_requests, &k);

    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        char msg[] = "could not write to l7_events - %ld";
        bpf_trace_printk(msg, sizeof(msg), r);
    }

    return 0;
}

// After socket creation and connection establishment, the kernel will call the
// write function of the socket's protocol handler to send data to the remote
// peer. The kernel will call the read function of the socket's protocol handler
// to receive data from the remote peer.

// Flow:
// 1. sys_enter_write
    // -- TODO: check if write was successful (return value), sys_exit_write ?
// 2. sys_enter_read
// 3. sys_exit_read


// In different programming languages, the syscalls might used in different combinations
// write - read
// send - recv
// sendto - recvfrom
// sendmmsg - recvfrom 
// sendmsg - recvmsg
// That's why we need to hook all of them
// and process the data in the same way

// sys_enter_ sending syscalls -- process_enter_of_syscalls_write_sendto
// sys_enter_ receiving syscalls -- process_enter_of_syscalls_read_recvfrom
// sys_exit_ receiving syscalls -- process_exit_of_syscalls_read_recvfrom

static __always_inline 
void ssl_uprobe_write_v_1_0_2(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_0_2 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v1_0_2 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio)) {         
        char msg3[] = "could not read bio";
        bpf_trace_printk(msg3, sizeof(msg3));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "ssl_uprobe_write_v_1_0_2 tls bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write_sendto(ctx, fd, 1, buf_ptr, buf_size);                   
}

static __always_inline 
void ssl_uprobe_read_enter_v1_0_2(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_0_2 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v1_0_2 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio)) {         
        char msg[] = "could not read rbio";
        bpf_trace_printk(msg, sizeof(msg));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "ssl_uprobe_read_enter_v1_0_2 bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
    char msg4[] = "tls read enter going to be processed";
    bpf_trace_printk(msg4, sizeof(msg4));

    process_enter_of_syscalls_read_recvfrom(id, pid, fd, buf_ptr, buf_size);            
}

static __always_inline 
void ssl_uprobe_write_v_1_1_1(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_1_1 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v1_1_1 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio)) {         
        char msg3[] = "could not read bio";
        bpf_trace_printk(msg3, sizeof(msg3));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "ssl_uprobe_write_v_1_1 tls bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write_sendto(ctx, fd, 1, buf_ptr, buf_size);                   
}

static __always_inline 
void ssl_uprobe_read_enter_v1_1_1(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v1_1_1 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v1_1_1 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio)) {         
        char msg[] = "could not read rbio";
        bpf_trace_printk(msg, sizeof(msg));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "ssl_uprobe_read_enter_v1_1 bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
    char msg4[] = "tls read enter going to be processed";
    bpf_trace_printk(msg4, sizeof(msg4));

    process_enter_of_syscalls_read_recvfrom(id, pid, fd, buf_ptr, buf_size);            
}


static __always_inline 
void ssl_uprobe_write_v_3(struct pt_regs *ctx, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v3_0_0 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v3_0 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.wbio)) {         
        char msg3[] = "could not read bio";
        bpf_trace_printk(msg3, sizeof(msg3));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "tls bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;

    process_enter_of_syscalls_write_sendto(ctx, fd, 1, buf_ptr, buf_size);                   
}

static __always_inline 
void ssl_uprobe_read_enter_v3(struct pt_regs *ctx, __u64 id,  __u32 pid, void* ssl, void* buffer, int num, size_t *count_ptr) {
    struct ssl_st_v3_0_0 ssl_st;
    bpf_probe_read_user(&ssl_st, sizeof(ssl_st), ssl);
    
    struct bio_st_v3_0 bio;                                                   
    if (bpf_probe_read(&bio, sizeof(bio), (void*)ssl_st.rbio)) {         
        char msg[] = "could not read rbio";
        bpf_trace_printk(msg, sizeof(msg));
        return;                                                       
    };                                                              
    __u32 fd = bio.num;

    char msg[] = "ssl_uprobe_read_enter bio->fd %ld";
    bpf_trace_printk(msg, sizeof(msg),fd);
    
    char* buf_ptr = (char*) buffer;               
    __u64 buf_size = num;
 
    char msg4[] = "tls read enter going to be processed";
    bpf_trace_printk(msg4, sizeof(msg4));

    process_enter_of_syscalls_read_recvfrom(id, pid, fd, buf_ptr, buf_size);            
}

SEC("tracepoint/syscalls/sys_enter_write")
int sys_enter_write(struct trace_event_raw_sys_enter_write* ctx) {
   return process_enter_of_syscalls_write_sendto(ctx, ctx->fd, 0, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_enter_sendto(struct trace_event_raw_sys_enter_sendto* ctx) {
   return process_enter_of_syscalls_write_sendto(ctx, ctx->fd, 0 ,ctx->buff, ctx->len);
}

SEC("tracepoint/syscalls/sys_exit_write")
int sys_exit_write(struct trace_event_raw_sys_exit_write* ctx) {
    return process_exit_of_syscalls_write_sendto(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_exit_sendto(struct trace_event_raw_sys_exit_sendto* ctx) {
    return process_exit_of_syscalls_write_sendto(ctx, ctx->ret);
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter_read* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return process_enter_of_syscalls_read_recvfrom(id, pid, ctx->fd, ctx->buf, ctx->count);
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_enter_recvfrom(struct trace_event_raw_sys_enter_recvfrom* ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    return process_enter_of_syscalls_read_recvfrom(id, pid, ctx->fd, ctx->ubuf, ctx->size);
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit_read* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return process_exit_of_syscalls_read_recvfrom(ctx, pid_tgid, pid, ctx->ret, 0);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_exit_recvfrom(struct trace_event_raw_sys_exit_recvfrom* ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    return process_exit_of_syscalls_read_recvfrom(ctx, pid_tgid, pid, ctx->ret, 0);
}

SEC("uprobe/SSL_write_v1_1_1")
void BPF_UPROBE(ssl_write_v1_1_1, void * ssl, void* buffer, int num) {
	ssl_uprobe_write_v_1_1_1(ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v1_1_1")
void BPF_UPROBE(ssl_read_enter_v1_1_1, void* ssl, void* buffer, int num) {
    char msg[] = "this is uprobe ssl_read_enter_v1_1_1";
    bpf_trace_printk(msg, sizeof(msg));
     
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v1_1_1(ctx, id, pid, ssl, buffer, num, 0);
}

SEC("uretprobe/SSL_read")
void BPF_URETPROBE(ssl_ret_read) {
	__u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;

    int returnValue = PT_REGS_RC(ctx);
    
    char msg[] = "this is uretprobe ssl_read ret: %ld";
    bpf_trace_printk(msg, sizeof(msg), returnValue);

    process_exit_of_syscalls_read_recvfrom(ctx, id, pid, returnValue, 1);
}

SEC("uprobe/SSL_write_v3")
void BPF_UPROBE(ssl_write_v3, void * ssl, void* buffer, int num) {
	ssl_uprobe_write_v_3(ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v3")
void BPF_UPROBE(ssl_read_enter_v3, void* ssl, void* buffer, int num) {
    char msg[] = "this is uprobe ssl_read_enter_v3";
    bpf_trace_printk(msg, sizeof(msg));
     
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v3(ctx, id, pid, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_write_v1_0_2")
void BPF_UPROBE(ssl_write_v1_0_2, void * ssl, void* buffer, int num) {
	ssl_uprobe_write_v_1_0_2(ctx, ssl, buffer, num, 0);
}

SEC("uprobe/SSL_read_v1_0_2")
void BPF_UPROBE(ssl_read_enter_v1_0_2, void* ssl, void* buffer, int num) {
    char msg[] = "this is uprobe ssl_read_enter_v1_0_2";
    bpf_trace_printk(msg, sizeof(msg));
     
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 id = pid_tgid | TLS_MASK;
    ssl_uprobe_read_enter_v1_0_2(ctx, id, pid, ssl, buffer, num, 0);
}

struct go_interface {
    __s64 type;
    void* ptr;
};

#if defined(__TARGET_ARCH_x86)
#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GOROUTINE(x) ((x)->r14)
#elif defined(__TARGET_ARCH_arm64) 
/* arm64 provides struct user_pt_regs instead of struct pt_regs to userspace */
#define GO_PARAM1(x) (((struct user_pt_regs *)(x))->regs[0])
#define GO_PARAM2(x) (((struct user_pt_regs *)(x))->regs[1])
#define GO_PARAM3(x) (((struct user_pt_regs *)(x))->regs[2])
#define GOROUTINE(x) (((struct user_pt_regs *)(x))->regs[28])
#endif


static __always_inline
int process_enter_of_go_conn_write(__u64 goid, __u32 pid, __u32 fd, char *buf_ptr, __u64 count) {
    // parse and write to go_active_l7_req map
    struct go_req_key k = {};
    k.pid = pid;
    k.fd = fd;

    int zero = 0;
    struct l7_request *req = bpf_map_lookup_elem(&go_l7_request_heap, &zero);
    if (!req) {
        return 0;
    }
    req->method = METHOD_UNKNOWN;
    req->protocol = PROTOCOL_UNKNOWN;
    req->payload_size = 0;
    req->payload_read_complete = 0;
    req->write_time_ns = bpf_ktime_get_ns();
    req->request_type = 0;

    if(buf_ptr){
        // try to parse only http1.1 for gotls reqs for now.
        int method = parse_http_method(buf_ptr);
        if (method != -1){
            req->protocol = PROTOCOL_HTTP;
            req-> method = method;
        }else{
            req->protocol = PROTOCOL_UNKNOWN;
            req->method = METHOD_UNKNOWN;
            return 0; 
        }
    }

    // copy req payload
    bpf_probe_read(&req->payload, MAX_PAYLOAD_SIZE, buf_ptr);
    if(count > MAX_PAYLOAD_SIZE){
        // will not be able to copy all of it
        req->payload_size = MAX_PAYLOAD_SIZE;
        req->payload_read_complete = 0;
    }else{
        req->payload_size = count;
        req->payload_read_complete = 1;
    }

    long res = bpf_map_update_elem(&go_active_l7_requests, &k, req, BPF_ANY);
    if(res < 0)
    {
		char msg[] = "go_active_l7_requests - %ld";
		bpf_trace_printk(msg, sizeof(msg), res);
    }

    return 0;
}

// (c *Conn) Write(b []byte) (int, error)
SEC("uprobe/go_tls_conn_write_enter")
int BPF_UPROBE(go_tls_conn_write_enter) {
    __u64 goid = GOROUTINE(ctx);
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    __u32 fd;
    struct go_interface conn;
    // Registers contain the function arguments
    
    // X0(arm64) register contains the pointer to the first function argument, c *Conn
    if (bpf_probe_read_user(&conn, sizeof(conn), (void*)GO_PARAM1(ctx))) {
        return 0;
    };
    void* fd_ptr;
    if (bpf_probe_read_user(&fd_ptr, sizeof(fd_ptr), conn.ptr)) {
        return 0;
    }
    
    if(!fd_ptr) {
        return 0;
    }
    if (bpf_probe_read_user(&fd, sizeof(fd), fd_ptr + 0x10)) {
        return 1;
    }

    // X1(arm64) register contains the byte ptr, pointing to first byte of the slice
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    // X2(arm64) register contains the length of the slice
    __u64 buf_size = GO_PARAM3(ctx);

    char msg[] = "go_tls_conn_write_enter fd: %ld";
    bpf_trace_printk(msg, sizeof(msg), fd);


    return process_enter_of_go_conn_write(goid, pid, fd, buf_ptr, buf_size);
}

// func (c *Conn) Read(b []byte) (int, error)
SEC("uprobe/go_tls_conn_read_enter")
int BPF_UPROBE(go_tls_conn_read_enter) {
    __u32 fd;
    struct go_interface conn;

    // X0(arm64) register contains the pointer to the first function argument, c *Conn
    if (bpf_probe_read_user(&conn, sizeof(conn), (void*)GO_PARAM1(ctx))) {
        return 1;
    };
    void* fd_ptr;
    if (bpf_probe_read_user(&fd_ptr, sizeof(fd_ptr), conn.ptr)) {
        return 1;
    }
    if (bpf_probe_read_user(&fd, sizeof(fd), fd_ptr + 0x10)) {
        return 1;
    }

    // X1(arm64) register contains the byte ptr, pointing to first byte of the slice
    char *buf_ptr = (char*)GO_PARAM2(ctx);
    // // X2(arm64) register contains the length of the slice
    __u64 buf_size = GO_PARAM3(ctx);

    char msg[] = "go_tls_conn_read_enter fd: %ld";
    bpf_trace_printk(msg, sizeof(msg), fd);


    struct go_read_args args = {};
    args.fd = fd;
    args.buf = buf_ptr;
    args.size = buf_size;
    args.read_start_ns = bpf_ktime_get_ns();

    struct go_read_key k = {};
    k.goid = GOROUTINE(ctx);
    k.pid = bpf_get_current_pid_tgid() >> 32;

    long res = bpf_map_update_elem(&go_active_reads, &k, &args, BPF_ANY);
    if(res < 0)
    {
        char msg[] = "Error writing to go_active_reads - %ld";
        bpf_trace_printk(msg, sizeof(msg), res);
    }
    return 0;
}

// attached to all RET instructions since uretprobe crashes go applications
SEC("uprobe/go_tls_conn_read_exit")
int BPF_UPROBE(go_tls_conn_read_exit) {
    // can't access to register we've access on read_enter here,
    // registers are changed.

    char msg[] = "go_tls_conn_read_exit go_uretprobe";
    bpf_trace_printk(msg, sizeof(msg));

    long int ret = GO_PARAM1(ctx);

    struct go_read_key k = {};
    k.goid = GOROUTINE(ctx);
    k.pid = bpf_get_current_pid_tgid() >> 32;

    struct go_read_args *read_args = bpf_map_lookup_elem(&go_active_reads, &k);
    if (!read_args) {
        return 0;
    }
    if(ret < 0){
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    // writeloop and readloop different goroutines

    struct go_req_key req_k = {};
    req_k.pid = k.pid;
    req_k.fd = read_args->fd;

    struct l7_request *req = bpf_map_lookup_elem(&go_active_l7_requests, &req_k);
    if (!req) {
        return 0;
    }

    int zero = 0;
    struct l7_event *e = bpf_map_lookup_elem(&l7_event_heap, &zero);
    if (!e) {
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    e->duration = bpf_ktime_get_ns() - req->write_time_ns;
    e->write_time_ns = req->write_time_ns;
    e->payload_size = req->payload_size;
    e->payload_read_complete = req->payload_read_complete;
    e->failed = 0; // success
    
    e->fd = read_args->fd;
    e->pid = k.pid;
    e->is_tls = 1;
    e->method = req->method;
    e->protocol = req->protocol;
    e->write_time_ns = req->write_time_ns;
    
    // request payload
    e->payload_size = req->payload_size;
    e->payload_read_complete = req->payload_read_complete;
    
    // copy req payload
    bpf_probe_read(e->payload, MAX_PAYLOAD_SIZE, req->payload);
    
    e->failed = 0; // success
    e->status = 0;
    // parse response payload
    if(read_args->buf && ret > PAYLOAD_PREFIX_SIZE){
        if(e->protocol == PROTOCOL_HTTP){ // if http, try to parse status code
            // read first 16 bytes of read buffer
            char buf_prefix[PAYLOAD_PREFIX_SIZE];
            long r = bpf_probe_read(&buf_prefix, sizeof(buf_prefix), (void *)(read_args->buf)) ;
            
            if (r < 0) {
                char msg[] = "go_tls_conn_read_exit could not read into buf_prefix - %ld";
                bpf_trace_printk(msg, sizeof(msg), r);
                bpf_map_delete_elem(&go_active_reads, &k);
                // bpf_map_delete_elem(&go_active_l7_requests, &req_k); // TODO: check ?
                return 0;
            }

            int status = parse_http_status(buf_prefix);
            if (status != -1){
                e->status = status;
            }else{
                // In case of write happens but read_exit probe doesn't get called for a request (sigkill of process?)
                // a read from the same socket (same pid-fd pair) after some time, can match with the previous write
                // if the latter is http1.1, requests can mismatch (if expression above will satisfy)
                // or(not http1.1) the status code will be 0 if continued processing.
                // So we'll clean up the request here if it's not a protocol we support before hand.
                // mismatches can still occur, but it's better than nothing.
                // TODO: find a solution for the mismatch problem

                bpf_map_delete_elem(&go_active_reads, &k);
                bpf_map_delete_elem(&go_active_l7_requests, &req_k);
                return 0;
            }
        }else{
            bpf_map_delete_elem(&go_active_reads, &k);
            return 0;
        }
    }else{
        char msgCtx[] = "go_tls_conn_read_exit read buffer is null or too small";
        bpf_trace_printk(msgCtx, sizeof(msgCtx));
        bpf_map_delete_elem(&go_active_reads, &k);
        return 0;
    }

    bpf_map_delete_elem(&go_active_reads, &k);
    bpf_map_delete_elem(&go_active_l7_requests, &req_k);

    long r = bpf_perf_event_output(ctx, &l7_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    if (r < 0) {
        char msg[] = "could not write gotls event to l7_events - %ld";
        bpf_trace_printk(msg, sizeof(msg), r);
    }

    return 0;
}

