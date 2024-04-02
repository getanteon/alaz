//go:build ignore

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

    #ifdef FILTER_OUT_NON_CONTAINER
    // try to remove pid from container_pids map(it may not exist, but it's ok)
    // since we add pids on sched_process_fork regardless of being process or thread
    // try to remove both pid and tid
    if (pid == tid){ // if it's a process, remove pid
        // process exiting
        bpf_map_delete_elem(&container_pids, &pid);
    }else{
        // thread exiting
        bpf_map_delete_elem(&container_pids, &tid);
    }
    #endif

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

SEC("tracepoint/sched/sched_process_fork")
int sched_process_fork(struct trace_event_raw_sched_process_fork* ctx)
{
    #ifdef FILTER_OUT_NON_CONTAINER
    // check parent pid is in container 
    // (ctx->pid can be a thread too, linux kernel treats threads and processes in the same way)
    // there is a spectrum between threads and processes in terms of sharing resources via flags.
    __u32 pid = ctx->pid;
    __u32 child_pid =ctx->child_pid;

    __u8 *is_container_pid = bpf_map_lookup_elem(&container_pids, &pid);
    if (!is_container_pid)
        return 0;

    unsigned char func_name[] = "sched_process_fork";
    __u8 exists = 1;
    // write child_pid to container_pids map
    long res = bpf_map_update_elem(&container_pids, &child_pid, &exists, BPF_ANY);
    if (res < 0){
        unsigned char log_msg[] = "failed forked task -- pid|child_pid|res";
        log_to_userspace(ctx, DEBUG, func_name, log_msg, ctx->pid,ctx->child_pid, res);     
    }else{
        unsigned char log_msg[] = "add forked task -- pid|child_pid|psize";
        log_to_userspace(ctx, DEBUG, func_name, log_msg, ctx->pid,ctx->child_pid, 0);        
    }
    #endif

    return 0;
}