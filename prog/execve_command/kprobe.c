// go:build ignore

#include "../../headers/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") output = {
    .type =
        BPF_MAP_TYPE_PERF_EVENT_ARRAY, // TODO: use PERF_EVENT_ARRAY instead?
    .key_size = 0,
    .value_size = 0,
    .max_entries = 4096, // TODO: why 4096?
};

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

SEC("kprobe/execve_command")
int get_command6(void *ctx) {
  struct data_t data = {};
  data.sample_type = 0x400; // PERF_SAMPLE_RAW;
  data.type = 0x1;          // PERF_TYPE_SOFTWARE;
  data.config = 0xa;        // PERF_COUNT_SW_BPF_OUTPUT;
  char message[12] = "Hello World";

  int pid = bpf_get_current_pid_tgid() >> 32;
  int uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  // reserve space in the ring buffer
  //   data = bpf_ringbuf_reserve(&output, sizeof(*data), 0);

  //   if (!data) {
  //     return 0;
  //   }

  data.pid = pid;
  data.uid = uid;

  bpf_get_current_comm(data.command, sizeof(data.command));
  bpf_probe_read_kernel(data.message, sizeof(data.message), message);

  // BPF_F_CURRENT_CPU
  long flags = 0xffffffff; // The *flags* are used to indicate the index in
  // *map* for which
  // * 	the value must be put
  long res = bpf_perf_event_output(ctx, &output, flags, &data, sizeof(data));
  if (res != 0) {
    //  TODO: fails because of -2 (ENOENT)
    const char *msg = "Fail -> **%d**";
    bpf_trace_printk(msg, 15, res);
  } else {
    const char *msg = "Success!";
    bpf_trace_printk(msg, 9);
  }

  // bpf_ringbuf_output(&output, &data, sizeof(data), 0);
  //   bpf_ringbuf_commit(data, 0, FALSE);
  //   bpf_ringbuf_discard(data, 0);

  // TODO: if icine koyarsan leak oluyo, unreleased diyor

  // TODO: include for BPF_RB_FORCE_WAKEUP use

  return 0;
}
