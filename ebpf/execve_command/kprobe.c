#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/tcp.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helper_defs.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, 0);
  __uint(value_size, 0);
  __uint(max_entries,4096);
} output2 SEC(".maps");

// struct {
//   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
//   __uint(key_size, sizeof(u32));
//   __uint(value_size, sizeof(u32));
// } output2 SEC(".maps");

// perf event
struct data_t {
  // must fields in a perf event
  int sample_type;
  int type;
  int config;

  int pid;
  int uid;
  char command[16];
  char message[12];
};

SEC("kprobe/sys_execve")
int get_command(void *ctx) {
  struct data_t data = {};
  data.sample_type = 0x400; // PERF_SAMPLE_RAW;
  data.type = 0x1;          // PERF_TYPE_SOFTWARE;
  data.config = 0xa;        // PERF_COUNT_SW_BPF_OUTPUT;
  char message[12] = "Hello World";

  int pid = bpf_get_current_pid_tgid() >> 32;
  int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  data.pid = pid;
  data.uid = uid;

  bpf_get_current_comm(data.command, sizeof(data.command));
  bpf_probe_read_kernel(data.message, sizeof(data.message), message);

  // BPF_F_CURRENT_CPU
  long flags = 0xffffffffULL; // The *flags* are used to indicate the index in
  // *map* for which
  // * 	the value must be put
  long res = bpf_perf_event_output(ctx, &output2, flags, &data, sizeof(data));
  if (res != 0) {
    //  TODO: fails because of -2 (ENOENT)
    const char *msg = "Fail -> **%d**";
    bpf_trace_printk(msg, 15, res);
  }

  return 0;
}
