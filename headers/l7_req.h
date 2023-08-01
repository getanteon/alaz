struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};


struct trace_event_raw_sys_enter_read{
    struct trace_entry ent;
    int __syscall_nr;
    unsigned long int fd;
    char * buf;
    __u64 count;
};

struct trace_event_raw_sys_enter_recvfrom {
    struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    void * ubuf;
    __u64 size;
    __u64 flags;
    struct sockaddr * addr;
    __u64 addr_len;
};

struct trace_event_raw_sys_exit_read {
    __u64 unused;
    __s32 id;
    __s64 ret;
};

struct trace_event_raw_sys_exit_recvfrom {
    __u64 unused;
    __s32 id;
    __s64 ret;
};



struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    char * buf;
    __u64 count;
};

// TODO: remove unused fields ?
struct trace_event_raw_sys_enter_sendto {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    void * buff;
    __u64 len; // size_t ??
    __u64 flags;
    struct sockaddr * addr;
    __u64 addr_len;
};

struct iovec
{
    void *iov_base;	/* Pointer to data.  */
    __u64 iov_len;	/* Length of data.  */
};


struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	void *msg_control;
	__kernel_size_t msg_controllen;
	unsigned int msg_flags;
};

struct trace_event_raw_sys_enter_sendmsg {
	struct trace_entry ent;
    __s32 __syscall_nr;
    __u64 fd;
    struct user_msghdr * msg;
    __u64 flags;
};



