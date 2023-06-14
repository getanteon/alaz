#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/tcp.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helper_defs.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct tcp_event {
  __u64 fd;
  __u64 timestamp;
  __u32 type;
  __u32 pid;
  __u16 sport;
  __u16 dport;
  __u8 saddr[16];
  __u8 daddr[16];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} tcp_listen_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(int));
  __uint(value_size, sizeof(int));
} tcp_connect_events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(__u64));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 10240);
} fd_by_pid_tgid SEC(".maps");

struct sk_info {
  __u64 fd;
  __u32 pid;
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size, sizeof(void *));
  __uint(value_size, sizeof(struct sk_info));
  __uint(max_entries, 10240);
} sk_info SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(key_size, sizeof(struct sk_info));
  __uint(value_size, sizeof(__u64));
  __uint(max_entries, 32768);
} connection_timestamps SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(void *ctx) {
  struct trace_event_raw_inet_sock_set_state args = {};
  if (bpf_core_read(&args, sizeof(args), ctx) < 0) {
    return 0;
  }

  // if not tcp protocol, ignore
  if (BPF_CORE_READ(&args, protocol) != IPPROTO_TCP) {
    return 0;
  }

  // get pid
  __u64 id = bpf_get_current_pid_tgid();
  __u32 pid = id >> 32;
  const void *skaddr;

  // if state transition is from BPF_TCP_CLOSE to BPF_TCP_SYN_SENT, a new
  // connection attempt

  int oldstate;
  int newstate;

  oldstate = BPF_CORE_READ(&args, oldstate);
  newstate = BPF_CORE_READ(&args, newstate);
  skaddr = BPF_CORE_READ(&args, skaddr);

  if (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_SYN_SENT) {
    // const char *msg = "close to syn_sent";
    // bpf_trace_printk(msg, 18);

    __u64 *fdp = bpf_map_lookup_elem(&fd_by_pid_tgid, &id);

    // if fdp == NULL (not found)
    if (!fdp) {
      return 0;
    }

    struct sk_info i = {};
    i.pid = pid;
    i.fd = *fdp; // file descriptor pointer

    // remove from fd_by_pid_tgid map, we are going to keep fdp
    bpf_map_delete_elem(&fd_by_pid_tgid, &id);
    bpf_map_update_elem(&sk_info, &skaddr, &i, BPF_ANY);
    return 0;
  }

  __u64 fd = 0;
  __u32 type = 0;
  __u64 timestamp = 0;
  void *map = &tcp_connect_events;
  if (oldstate == BPF_TCP_SYN_SENT) {
    struct sk_info *i = bpf_map_lookup_elem(&sk_info, &skaddr);
    if (!i) {
      return 0;
    }
    if (newstate == BPF_TCP_ESTABLISHED) {
      // const char *msg = "established";
      // bpf_trace_printk(msg, 12);

      timestamp = bpf_ktime_get_ns(); // time elapsed since system boot
      struct sk_info k = {};
      k.pid = i->pid;
      k.fd = i->fd;
      bpf_map_update_elem(&connection_timestamps, &k, &timestamp, BPF_ANY);
      type = EVENT_TYPE_CONNECTION_OPEN;
    } else if (newstate == BPF_TCP_CLOSE) {
      type = EVENT_TYPE_CONNECTION_ERROR;
    }
    pid = i->pid;
    fd = i->fd;
    bpf_map_delete_elem(&sk_info, &skaddr);
  }
  if (oldstate == BPF_TCP_ESTABLISHED &&
      (newstate == BPF_TCP_FIN_WAIT1 || newstate == BPF_TCP_CLOSE_WAIT)) {
    pid = 0;
    type = EVENT_TYPE_CONNECTION_CLOSE;
  }
  if (oldstate == BPF_TCP_CLOSE && newstate == BPF_TCP_LISTEN) {
    type = EVENT_TYPE_LISTEN_OPEN;
    map = &tcp_listen_events;
  }
  if (oldstate == BPF_TCP_LISTEN && newstate == BPF_TCP_CLOSE) {
    type = EVENT_TYPE_LISTEN_CLOSE;
    map = &tcp_listen_events;
  }

  if (type == 0) {
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

struct trace_event_raw_args_with_fd__stub {
  __u64 unused;
  long int id;
  __u64 fd;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(void *ctx) {
  struct trace_event_raw_args_with_fd__stub args = {};
  // TODO: use bpf_core_read for portability
  if (bpf_probe_read(&args, sizeof(args), ctx) < 0) {
    return 0;
  }
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&fd_by_pid_tgid, &id, &args.fd, BPF_ANY);
  struct sk_info k = {};
  k.pid = id >> 32;
  k.fd = args.fd;
  bpf_map_delete_elem(&connection_timestamps, &k);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int sys_exit_connect(void *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  bpf_map_delete_elem(&fd_by_pid_tgid, &id);
  return 0;
}
