//go:build ignore

#include "../headers/bpf.h"
#include "../headers/common.h"
#include "../headers/tcp.h"
#include "../headers/l7_req.h"


// order is important
#ifndef __BPF__H
#define __BPF__H
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#endif

#define FILTER_OUT_NON_CONTAINER

#include <stddef.h>
#include "../headers/pt_regs.h"
#include <sys/socket.h>

#include "../headers/log.h"

#include "macros.h"
#include "struct.h"
#include "map.h"

#include "tcp.c"
#include "proc.c"

#include "http.c"
#include "amqp.c"
#include "postgres.c"
#include "redis.c"
#include "openssl.c"
#include "http2.c"
#include "tcp_sock.c"
#include "go_internal.h"
#include "l7.c"

char __license[] SEC("license") = "Dual MIT/GPL";


