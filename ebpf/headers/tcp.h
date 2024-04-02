struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_event_raw_inet_sock_set_state {
	struct trace_entry ent;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

typedef unsigned short int sa_family_t;

struct sockaddrv
{
  sa_family_t sa_family;
  char sa_data[14];
};

struct trace_event_sys_enter_connect
{
  struct trace_entry ent;
  int __syscall_nr;
  long unsigned int fd;
  struct sockaddrv *uservaddr;
  long unsigned int addrlen;
};


#define EVENT_TCP_ESTABLISHED	1
#define EVENT_TCP_CONNECT_FAILED		2
#define EVENT_TCP_LISTEN	3
#define EVENT_TCP_LISTEN_CLOSED	4
#define EVENT_TCP_CLOSED	5
