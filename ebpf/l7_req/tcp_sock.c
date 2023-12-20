#define INGRESS 0
#define EGRESS 1

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ingress_egress_calls SEC(".maps");


struct call_event {
    __u32 pid;
    __u32 tid;
    __u64 tx; // timestamp
    __u8 type; // INGRESS or EGRESS
    __u32 seq; // tcp sequence number
};

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

static __always_inline
struct tcp_sock * get_tcp_sock(__u32 fd_num){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 pid = BPF_CORE_READ(task, pid);
    __u32 tgid = BPF_CORE_READ(task, tgid);

    char msgPid [] = "pid %d tgid %d\n";
    bpf_trace_printk(msgPid, sizeof(msgPid), pid, tgid);

    atomic_t count = BPF_CORE_READ(task, files, count);
    
    char msgFiles [] = "files count %d\n";
    bpf_trace_printk(msgFiles, sizeof(msgFiles), count.counter);

    struct file **fdarray = NULL;
    fdarray = BPF_CORE_READ(task, files, fdt, fd);

    if(fdarray == NULL){
        char msg[] = "fdarray is null";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }else{
        struct file *file = NULL;
        long r = bpf_probe_read_kernel(&file, sizeof(file), fdarray + fd_num);
        if(r <0){
            char msg[] = "could not read file %d/n";
            bpf_trace_printk(msg, sizeof(msg), r);
            return 0;
        }

        char msg[] = "file %d\n";
        bpf_trace_printk(msg, sizeof(msg), file);

        void * private_data = NULL;
        private_data = BPF_CORE_READ(file, private_data);
       
        if(private_data == NULL){
            char msg2[] = "private data is null";
            bpf_trace_printk(msg2, sizeof(msg2));
        }else{
            char msg2[] = "private data is NOT null";
            bpf_trace_printk(msg2, sizeof(msg2));

            struct socket *socket = private_data;
            short int socket_type = BPF_CORE_READ(socket,type);

            void * __file = BPF_CORE_READ(socket,file);

            char msg3[] = "socket_type %d\n";
            bpf_trace_printk(msg3, sizeof(msg3), socket_type);

            if(socket_type == SOCK_STREAM && file == __file ){
                char msg4[] = "socket_type is stream\n";
                bpf_trace_printk(msg4, sizeof(msg4));

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
    char msg[] = "tcp_sock is null";
    bpf_trace_printk(msg, sizeof(msg));
    return 0;
  }

  __u32 tcp_seq = 0;
  tcp_seq = BPF_CORE_READ(__tcp_sock,write_seq);

  char msg5[] = "write_seq %u\n";
  bpf_trace_printk(msg5, sizeof(msg5), tcp_seq);

  return tcp_seq;
}


static __always_inline
__u32 get_tcp_copied_seq_from_fd(__u32 fd_num){
    struct tcp_sock * __tcp_sock =  (struct tcp_sock *) get_tcp_sock(fd_num);
    if(__tcp_sock == NULL){
        char msg[] = "tcp_sock is null";
        bpf_trace_printk(msg, sizeof(msg));
        return 0;
    }

   __u32 tcp_seq = 0;
    tcp_seq = BPF_CORE_READ(__tcp_sock,copied_seq);

    char msg5[] = "copied_seq %u\n";
    bpf_trace_printk(msg5, sizeof(msg5), tcp_seq);
    
    return tcp_seq;    
}

static __always_inline
__u64 process_for_dist_trace_write(__u64 fd){
  struct call_event *e;
  __u32 pid, tid;
  __u64 id = 0;

  /* get PID and TID of exiting thread/process */
  id = bpf_get_current_pid_tgid();
  pid = id >> 32;
  tid = (__u32)id;

  __u32 seq = get_tcp_write_seq_from_fd(fd);

  /* reserve sample from BPF ringbuf */
  e = bpf_ringbuf_reserve(&ingress_egress_calls, sizeof(*e), 0);
  if (!e)
    return 0;
  e->pid = pid;
  e->tid = tid;
  e->seq = seq;
  e->tx = bpf_ktime_get_ns();
  e->type = EGRESS;

  bpf_ringbuf_submit(e, 0);

  return seq;
}

static __always_inline
void process_for_dist_trace_read(__u32 fd){
    struct call_event *e;
    __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    __u32 seq = get_tcp_copied_seq_from_fd(fd);

    /* reserve sample from BPF ringbuf */
    e = bpf_ringbuf_reserve(&ingress_egress_calls, sizeof(*e), 0);
    if (!e)
        return;
    e->pid = pid;
    e->tid = tid;
    e->seq = seq;
    e->tx = bpf_ktime_get_ns();
    e->type = INGRESS;

    bpf_ringbuf_submit(e, 0);
}
