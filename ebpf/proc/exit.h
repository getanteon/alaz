#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct pexit_event {
    int pid;
};

struct trace_event_raw_sched_process_template {
    __u64 unused;
    char comm[TASK_COMM_LEN];
    __u32 pid;
};
