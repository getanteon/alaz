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

