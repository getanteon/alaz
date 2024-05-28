// Log levels
#define DEBUG 0
#define INFO 1
#define WARN 2
#define ERROR 3

#define LOG_MSG_SIZE 100

// bpf_trace_printk()
// %s, %d, and %c work
// %pi6 for ipv6 address
// $pks for kernel strings
// can accept only up to 3 input arguments (bpf helpers can accept up to 5 in total)

struct log_message {
	__u32 level;
    // specify the what are the arguments in log message
    // Args:[type, type, type] -- log message
    unsigned char log_msg[LOG_MSG_SIZE];
    unsigned char func_name[LOG_MSG_SIZE];
    __u32 pid;
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 10240);
} log_map SEC(".maps");

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct log_message);
     __uint(max_entries, 1);
} log_heap SEC(".maps");

// use while development
//    struct log_message l = {};
//    l.level = DEBUG;
//    BPF_SNPRINTF(l.payload, sizeof(l.payload),"process_enter_of_syscalls_write_sendto %d %s\n", 1, "cakir");
//    log_to_trace_pipe(l.payload, sizeof(l.payload));
static __always_inline
void log_to_trace_pipe(char *msg, __u32 size) {
   long res = bpf_trace_printk(msg, size);
   if(res < 0){
      bpf_printk("bpf_trace_printk failed %d\n", res);
   }
}

static __always_inline 
void log_to_userspace(void *ctx, __u32 level, unsigned char *func_name, unsigned char * log_msg, __u64 arg1, __u64 arg2, __u64 arg3){
    int zero = 0;
    struct log_message *l = bpf_map_lookup_elem(&log_heap, &zero);
    if (!l) {
        bpf_printk("log_to_userspace failed, %s %s\n",func_name, log_msg);
        return;
    }

    l->level = level;
    l->pid = bpf_get_current_pid_tgid() >> 32;
    l->arg1 = arg1;
    l->arg2 = arg2;
    l->arg3 = arg3;
    bpf_probe_read_str(&l->func_name, sizeof(l->func_name), func_name);
    bpf_probe_read_str(&l->log_msg, sizeof(l->log_msg), log_msg);
    
    bpf_perf_event_output(ctx, &log_map, BPF_F_CURRENT_CPU, l, sizeof(*l));
}


