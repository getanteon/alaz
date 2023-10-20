# Alaz Architecture
Alaz is designed to run in a kubernetes cluster as an agent, deployed as Daemonset (runs on each cluster node separately).

What it does is to watch and pull data from cluster to gain visibility onto the cluster.

It gathers information from 3 different sources:
 
## 1- Kubernetes Client
Using kubernetes client, it polls different type of events related to kubernetes resources. Like **ADD, UPDATE, DELETE** events for any kind of K8s resources like **Pods,Deployments,Services** etc.

	 Packages used: 
- 	 `k8s.io/api/core/v1`
- 	 `k8s.io/apimachinery/pkg/util/runtime`
- 	 `k8s.io/client-go`

## 2- Container Runtimes (containerd)
There are different types of container runtimes available for K8s clusters like containerd, crio, docker etc.
By connecting to chosen container runtimes socket, Alaz is able to gather more detailed information on containers running on nodes.
- log directory of the container,
- information related to its sandbox,
- pid,
- cgroups
- environment variables
- ...

> We do not take into consideration container runtimes data, we do not need it for todays objectives. Will be used later on for collecting more detailed data.

## 3- eBPF Programs

In Alaz's eBPF directory there are a couple of **eBPF programs written in C using libbpf**.

In order to compile these programs, we have a **eBPF-builder image** that contains necessary dependencies installed like **clang, llvm, libbpf and go**.

eBPF programs are compiled in mentioned container, leveraging [Cilium bpf2go package](https://github.com/cilium/ebpf/tree/main/cmd/bpf2go).

Using go generate directive with `bpf2go`, it compiles the eBPF program and generated necessary helper files in go in order us to interact with eBPF programs. 

- Link the program to a tracepoint or a kprobe. 
- Read bpf maps from user space and pass them for sense-making of data.

Used packages from cilium are :
 - `github.com/cilium/eBPF/link`
 - `github.com/cilium/eBPF/perf`
 - `github.com/cilium/eBPF/rlimit`

 eBPF programs: 
 - `tcp_state` : Detects newly established, closed, and listened TCP connections. The number of sockets associated with the program's PID depends on the remote IP address. Keeping this data together with the file descriptor is useful.
 - `l7_req` : Monitors both incoming and outgoing payloads by tracking the write,read syscalls and uprobes. Then use `tcp_state` to aggregate the data we receive, allowing us to determine who sent which request to where.
 
Current  programs are generally attached to kernel tracepoints like:

```
tracepoint/syscalls/sys_enter_write (l7_req)
tracepoint/syscalls/sys_exit_write (l7_req)
tracepoint/syscalls/sys_enter_sendto (l7_req)
tracepoint/syscalls/sys_exit_sendto (l7_req)
tracepoint/syscalls/sys_enter_read (l7_req)
tracepoint/syscalls/sys_exit_read (l7_req)
tracepoint/syscalls/sys_enter_recvfrom (l7_req)
tracepoint/syscalls/sys_exit_recvfrom (l7_req)
tracepoint/sock/inet_sock_set_state (tcp_state)
tracepoint/syscalls/sys_enter_connect (tcp_state)
tracepoint/syscalls/sys_exit_connect (tcp_state)
```

uprobes:
```
SSL_write
SSL_read
crypto/tls.(*Conn).Write
crypto/tls.(*Conn).Read
```

#### Note: 
Uretprobes crashes go applications. (https://github.com/iovisor/bcc/issues/1320)
That's why we disassemble the executable and find return instructions addresses and attach classic uprobes on them as a workaround.

## How to Build Alaz
Alaz embeds compiled eBPF programs in it. After compilation process on eBPF-builder is done, compiled programs are located in project structure.

Using **//go:embed** directive of golang. We embed *.o* files and load them into kernel using [Cilium eBPF package](https://github.com/cilium/eBPF).

Then we build Alaz like a ordinary golang app more or less since compiled codes are embedded.

#### How to Deploy Alaz
Deployed as a privileged DaemonSet resource on the cluster. Alaz is required to run as a privileged container since it needs read access to `/proc` directory of the host machine.

And Alaz's `serviceAccount` must be should be associated with `ClusterRole` and `ClusterRoleBinding` resources in order to be able to talk with K8s server.
