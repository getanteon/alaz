// +build !exclude

#include "../../headers/common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counter_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(u64),
    .max_entries = 10240,
};

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
