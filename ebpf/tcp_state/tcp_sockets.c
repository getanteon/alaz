//go:build ignore
#include "../headers/bpf.h"
#include "../headers/common.h"
#include "../headers/tcp.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

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

// used for sending events to user space
// EVENT_TCP_LISTEN, EVENT_TCP_LISTEN_CLOSED
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} tcp_listen_events SEC(".maps");

// used for sending events to user space
// EVENT_TCP_ESTABLISHED, EVENT_TCP_CLOSED, EVENT_TCP_CONNECT_FAILED
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} tcp_connect_events SEC(".maps");

// keeps the pid and fd of the process that opened the socket
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

// pid and fd of socket
struct sk_info
{
  __u64 fd;
  __u32 pid;
};

// keeps open sockets
// key: skaddr
// value: sk_info
// remove when connection is established or when socket is closed
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, void *);
  __type(value, struct sk_info);
} sock_map SEC(".maps");


// opening sockets, delete when connection is established or connection fails
struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, void *);
  __type(value, struct sk_info);
} sock_map_temp SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx)
{
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

  bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, &e, sizeof(e));

  return 0;
}

// triggered before entering connect syscall
SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx)
{
  struct trace_event_sys_enter_connect args = {};
  if (bpf_core_read(&args, sizeof(args), ctx) < 0)
  {
    return 0;
  }
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(void *ctx)
{
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fd_by_pid_tgid, &id);
  return 0;
}
