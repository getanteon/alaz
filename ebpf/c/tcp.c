//go:build ignore
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx)
{
    unsigned char func_name[] = "inet_sock_set_state";
  __u64 timestamp = bpf_ktime_get_ns();
  struct trace_event_raw_inet_sock_set_state args = {};
  if (bpf_core_read(&args, sizeof(args), ctx) < 0)
  {
    return 0;
  }

  // if not tcp protocol, ignore
  if (BPF_CORE_READ(&args, protocol) != IPPROTO_TCP)
  {
    return 0;
  }

  // get pid
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = id >> 32;

  const void *skaddr;

  // if state transition is from BPF_TCP_CLOSE to BPF_TCP_SYN_SENT,
  // a new connection attempt

  int oldstate;
  int newstate;

  oldstate = BPF_CORE_READ(&args, oldstate);
  newstate = BPF_CORE_READ(&args, newstate);
  skaddr = BPF_CORE_READ(&args, skaddr);

  if (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_SYN_SENT)
  {
    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);

    if (!fdp)
    {
      return 0;
    }

    struct sk_info i = {};
    i.pid = pid;
    i.fd = *fdp; // file descriptor pointer

    // remove from fd_by_pid_tgid map, we are going to keep fdp
    bpf_map_delete_elem(&fd_by_pid_tgid, &id);
    bpf_map_update_elem(&sock_map_temp, &skaddr, &i, BPF_ANY);
    return 0;
  }

  __u64 fd = 0;
  __u32 type = 0;
  
  void *map = &tcp_connect_events;
  if (oldstate == BPF_TCP_SYN_SENT)
  {
    struct sk_info *i = bpf_map_lookup_elem(&sock_map_temp, &skaddr);
    if (!i)
    {
      return 0;
    }
    if (newstate == BPF_TCP_ESTABLISHED)
    {
      type = EVENT_TCP_ESTABLISHED;
      pid = i->pid;
      fd = i->fd;
      bpf_map_delete_elem(&sock_map_temp, &skaddr);

      // add to sock_map
      struct sk_info si = {};
      si.pid = i->pid;
      si.fd = i->fd;
      bpf_map_update_elem(&sock_map, &skaddr, &si, BPF_ANY);
    }
    else if (newstate == BPF_TCP_CLOSE)
    {
      type = EVENT_TCP_CONNECT_FAILED;
      pid = i->pid;
      fd = i->fd;
      bpf_map_delete_elem(&sock_map_temp, &skaddr);
    } 
  }

  if (oldstate == BPF_TCP_ESTABLISHED &&
      (newstate == BPF_TCP_FIN_WAIT1 || newstate == BPF_TCP_CLOSE_WAIT))
  {
    type = EVENT_TCP_CLOSED;
    
    struct sk_info *i = bpf_map_lookup_elem(&sock_map, &skaddr);
    if (!i)
    {
      return 0;
    }
    pid = i->pid;
    fd = i->fd;

    // delete from sock_map
    bpf_map_delete_elem(&sock_map, &skaddr);
  }
  if (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_LISTEN)
  {
    type = EVENT_TCP_LISTEN;
    map = &tcp_listen_events;
  }
  if (oldstate == BPF_TCP_LISTEN && newstate == BPF_TCP_CLOSE)
  {
    type = EVENT_TCP_LISTEN_CLOSED;
    map = &tcp_listen_events;
  }

  if (type == 0)
  {
    return 0;
  }

  struct tcp_event e = {};
  e.type = type;
  e.timestamp = timestamp;
  e.pid = pid;
  e.sport = BPF_CORE_READ(&args, sport);
  e.dport = BPF_CORE_READ(&args, dport);
  e.fd = fd;

  __builtin_memcpy(&e.saddr, &args.saddr, sizeof(e.saddr));
  __builtin_memcpy(&e.daddr, &args.daddr, sizeof(e.saddr));

  __u8 *val = bpf_map_lookup_elem(&container_pids, &e.pid);
  if (!val)
  {
    // unsigned char log_msg[] = "tcp connect event filtered -- pid|fd|psize";
    // log_to_userspace(ctx, DEBUG, func_name, log_msg, pid, 0, 0);        

    return 0; // not a container process, ignore    
  }

  bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, &e, sizeof(e));
  return 0;
}

// triggered before entering connect syscall
SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx)
{
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = id >> 32;

  __u8 *val = bpf_map_lookup_elem(&container_pids, &pid);
  if (!val)
  {
    return 0; // not a container process, ignore
  }

  struct trace_event_sys_enter_connect args = {};
  if (bpf_core_read(&args, sizeof(args), ctx) < 0)
  {
    return 0;
  }
  bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(void *ctx)
{
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = id >> 32;

  __u8 *val = bpf_map_lookup_elem(&container_pids, &pid);
  if (!val)
  {
    return 0; // not a container process, ignore
  }

  bpf_map_delete_elem(&fd_by_pid_tgid, &id);
  return 0;
}
