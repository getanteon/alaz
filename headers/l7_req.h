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

struct trace_event_raw_sys_enter_rw__stub {
    __u64 unused;
    long int id;
    __u64 fd;
    char* buf;
    __u64 size;
};

struct trace_event_raw_sys_enter_write {
	struct trace_entry ent;
    int __syscall_nr;
    unsigned int fd;
    char * buf; // TODO
    __u64 count;
};

struct trace_event_raw_sys_enter_read{
    struct trace_entry ent;
    int __syscall_nr;
    unsigned int fd;
    char * buf;
    __u64 count;
};



