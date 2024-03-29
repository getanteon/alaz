//go:build ignore

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


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 5000);
} container_pids SEC(".maps");

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
