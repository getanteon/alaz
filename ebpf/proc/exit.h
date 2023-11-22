#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define PROC_EXEC_EVENT 1
#define PROC_EXIT_EVENT 2


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
