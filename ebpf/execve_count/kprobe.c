#include "../../headers/bpf.h"
#include "../../headers/common.h"
#include "../../headers/tcp.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helper_defs.h>


char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size,  sizeof(u32));
  __uint(value_size, sizeof(u64));
  __uint(max_entries,1);
} kprobe_map SEC(".maps");

SEC("kprobe/sys_execve")
int kprobe_execve() {
  u32 key = 0;
  u64 initval = 1;
  u64 *valp;

  const char *msg = "Hello World!";
  bpf_trace_printk(msg, 13);

  valp = bpf_map_lookup_elem(&kprobe_map, &key);
  if (!valp) { // if null, add to map with initval
    bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
    return 0;
  }
  __sync_fetch_and_add(valp, 1);

  return 0;
}
