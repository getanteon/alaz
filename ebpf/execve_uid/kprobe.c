#include "../../headers/common.h"
#include "../../headers/bpf.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helper_defs.h>
#include "../../headers/tcp.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(key_size,  sizeof(u64));
  __uint(value_size, sizeof(u64));
} counter_table SEC(".maps");

SEC("kprobe/hello")
int hello(void *ctx) {
  u64 uid;
  u64 counter = 0;
  u64 *p;

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  p = bpf_map_lookup_elem(&counter_table, &uid); // lookup the counter
  if (p != 0) {
    counter = *p;
  }
  counter++;
  bpf_map_update_elem(&counter_table, &uid, &counter,
                      BPF_ANY); // update the counter
  return 0;
}
