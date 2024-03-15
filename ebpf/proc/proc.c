//go:build ignore
#include "../headers/bpf.h"
#include "../headers/common.h"
#include "exit.h"


#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct p_event{
    __u32 pid;
    __u8 type;
};

struct {
     __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
     __type(key, __u32);
     __type(value, struct p_event);
     __uint(max_entries, 1);
} proc_event_heap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} proc_events SEC(".maps");


SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(struct trace_event_raw_sched_process_exec* ctx)
{
    __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;

    int zero = 0;
    struct p_event *e = bpf_map_lookup_elem(&proc_event_heap, &zero);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->type = PROC_EXEC_EVENT;
    
    bpf_perf_event_output(ctx, &proc_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(struct trace_event_raw_sched_process_exit* ctx)
{
    __u32 pid, tid;
    __u64 id = 0;

    /* get PID and TID of exiting thread/process */
    id = bpf_get_current_pid_tgid();
    pid = id >> 32;
    tid = (__u32)id;

    /* ignore thread exits */
    if (pid != tid)
        return 0;
    
    int zero = 0;
    struct p_event *e = bpf_map_lookup_elem(&proc_event_heap, &zero);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->type = PROC_EXIT_EVENT;
    
    bpf_perf_event_output(ctx, &proc_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
    return 0;
}
