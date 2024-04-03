
//go:build ignore
struct tcp_event
{
  __u64 fd;
  __u64 timestamp;
  __u32 type;
  __u32 pid;
  __u16 sport;
  __u16 dport;
  __u8 saddr[16];
  __u8 daddr[16];
};

// pid and fd of socket
struct sk_info
{
  __u64 fd;
  __u32 pid;
};

struct trace_event_raw_sched_process_exit {
    __u64 unused;
    char comm[TASK_COMM_LEN];
    __u32 pid;
};

struct trace_event_raw_sched_process_exec {
    __u64 unused;
    __u32 filename_unused;
    __u32 pid;
};

struct trace_event_raw_sched_process_fork {
    __u64 unused;
     char parent_comm[TASK_COMM_LEN];
    __u32 pid;
    char child_comm[TASK_COMM_LEN];
    __u32 child_pid;
};