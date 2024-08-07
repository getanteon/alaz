//go:build ignore
#define INGRESS 0
#define EGRESS 1

struct call_event {
    __u32 pid;
    __u32 tid;
    __u64 tx; // timestamp
    __u8 type; // INGRESS or EGRESS
    __u32 seq; // tcp sequence number
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct call_event);
     __uint(max_entries, 1);
} ingress_egress_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} ingress_egress_calls SEC(".maps");

struct file {
    void *private_data;
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;    /* current fd array, struct file *  */
};

typedef struct {
	int counter;
} atomic_t;

struct files_struct {
    atomic_t count; // atomic_t count;
    struct fdtable *fdt; 
};

struct task_struct {
    __u32 pid; // equals to POSIX tid
    __u32 tgid; // equals to POSIX pid
    struct files_struct *files;
};

struct socket {
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
};
struct tcp_sock {
	__u32 write_seq;
    __u32 copied_seq;
};

typedef __u32 __bitwise __portpair;
typedef __u64 __bitwise __addrpair;

struct sock_common {
    union {
		__addrpair	skc_addrpair;
		struct {
			__be32	skc_daddr;
			__be32	skc_rcv_saddr;
		};
	};
	union  {
		unsigned int	skc_hash;
		__u16		skc_u16hashes[2];
	};
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair	skc_portpair;
		struct {
			__be16	skc_dport;
			__u16	skc_num;
		};
	};

};

struct sock {
	struct sock_common	__sk_common;
    // __be32	sk_rcv_saddr; // not inet_saddr
    // __be16  sk_num; // local port, not inet_sport
    // __be32	sk_daddr;
    // __be16	sk_dport;
#define sk_rcv_saddr		__sk_common.skc_rcv_saddr
#define sk_daddr		__sk_common.skc_daddr
#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
};

static __always_inline
struct sock * get_sock(__u32 fd_num) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file **fdarray = NULL;
    fdarray = BPF_CORE_READ(task, files, fdt, fd);

    if(fdarray == NULL){
        return NULL;
    }else{
        struct file *file = NULL;
        long r = bpf_probe_read_kernel(&file, sizeof(file), fdarray + fd_num);
        if(r <0){
            return NULL;
        }

        void * private_data = NULL;
        private_data = BPF_CORE_READ(file, private_data);
        if(private_data){
            struct socket *socket = private_data;
            short int socket_type = BPF_CORE_READ(socket,type);

            void * __file = BPF_CORE_READ(socket,file);

            if(socket_type == SOCK_STREAM && file == __file){
                struct sock *sk = NULL;
                sk = BPF_CORE_READ(socket,sk);
            
                return sk;
            }
            return NULL;
        }
        return NULL;
    }
    return NULL;
}

static __always_inline
struct tcp_sock * get_tcp_sock(__u32 fd_num){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    // __u32 pid = BPF_CORE_READ(task, pid);
    // __u32 tgid = BPF_CORE_READ(task, tgid);

    // atomic_t count = BPF_CORE_READ(task, files, count);

    struct file **fdarray = NULL;
    fdarray = BPF_CORE_READ(task, files, fdt, fd);

    if(fdarray == NULL){
        return 0;
    }else{
        struct file *file = NULL;
        long r = bpf_probe_read_kernel(&file, sizeof(file), fdarray + fd_num);
        if(r <0){
            return 0;
        }

        void * private_data = NULL;
        private_data = BPF_CORE_READ(file, private_data);
       
        if(private_data){
            struct socket *socket = private_data;
            short int socket_type = BPF_CORE_READ(socket,type);

            void * __file = BPF_CORE_READ(socket,file);

            if(socket_type == SOCK_STREAM && file == __file ){
                struct sock *sk = NULL;
                sk = BPF_CORE_READ(socket,sk);

                if(sk != NULL){
                    struct tcp_sock * __tcp_sock = (struct tcp_sock *)sk;
                    return __tcp_sock;
                }
            }
        }
    }
    return  NULL;
}


static __always_inline
__u32 get_tcp_write_seq_from_fd(__u32 fd_num){
    struct tcp_sock * __tcp_sock =  (struct tcp_sock *) get_tcp_sock(fd_num);
    if(__tcp_sock == NULL){
        return 0;
    }

    __u32 tcp_seq = 0;
    tcp_seq = BPF_CORE_READ(__tcp_sock,write_seq);
    return tcp_seq;
}


static __always_inline
__u32 get_tcp_copied_seq_from_fd(__u32 fd_num){
    struct tcp_sock * __tcp_sock =  (struct tcp_sock *) get_tcp_sock(fd_num);
    if(__tcp_sock == NULL){
        return 0;
    }

   __u32 tcp_seq = 0;
    tcp_seq = BPF_CORE_READ(__tcp_sock,copied_seq);
    
    return tcp_seq;    
}

static __always_inline
__u64 process_for_dist_trace_write(void* ctx, __u64 fd){
    // unsigned char func_name[] = "process_for_dist_trace_write";
   __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    __u32 seq = get_tcp_write_seq_from_fd(fd);
    if(seq == 0){
        return 0;
    }

    int zero = 0;
    struct call_event *e = bpf_map_lookup_elem(&ingress_egress_heap, &zero);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->tid = tid;
    e->seq = seq;
    e->tx = bpf_ktime_get_ns();
    e->type = EGRESS;

    __u8 *val = bpf_map_lookup_elem(&container_pids, &(e->pid));
    if (!val)
    {
        // unsigned char log_msg[] = "filter out traffic egress event -- pid|fd|psize";
        // log_to_userspace(ctx, DEBUG, func_name, log_msg, e->pid, 0, 0);        
        return 0; // not a container process, ignore    
    }
    bpf_perf_event_output(ctx, &ingress_egress_calls, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return seq;
}

static __always_inline
void process_for_dist_trace_read(void* ctx, __u32 fd){
    // unsigned char func_name[] = "process_for_dist_trace_read";
    __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    __u32 seq = get_tcp_copied_seq_from_fd(fd);
    if(seq == 0){
        return;
    }

    int zero = 0;
    struct call_event *e = bpf_map_lookup_elem(&ingress_egress_heap, &zero);
    if (!e) {
        return;
    }

    e->pid = pid;
    e->tid = tid;
    e->seq = seq;
    e->tx = bpf_ktime_get_ns();
    e->type = INGRESS;

     __u8 *val = bpf_map_lookup_elem(&container_pids, &(e->pid));
    if (!val)
    {
        // unsigned char log_msg[] = "filter out traffic ingress event -- pid|fd|psize";
        // log_to_userspace(ctx, DEBUG, func_name, log_msg, e->pid, 0, 0);        
        return; // not a container process, ignore    
    }
    bpf_perf_event_output(ctx, &ingress_egress_calls, BPF_F_CURRENT_CPU, e, sizeof(*e));
}
