### Alaz Architecture
Alaz is designed to run in a kubernetes cluster as an agent, deployed as daemonset.(runs on each cluster node seperately).

What it does is to watch and pull data from cluster to gain visibility onto the cluster.

It gathers information from 3 different sources:
 
##### #  	1) Kubernetes Client
Using kubernetes client, it polls different type of events related to kubernetes resources. Like **ADD, UPDATE, DELETE** events for any kind of k8s resources like **Pods,Deployments,Services** etc.

	 Packages used: 
- 	 `k8s.io/api/core/v1`
- 	 `k8s.io/apimachinery/pkg/util/runtime`
- 	 `k8s.io/client-go`

##### #  	2) Container Runtimes (containerd)
There are different types of container runtimes available for k8s clusters like containerd,crio,docker etc.
By connecting to chosen container runtimes socket, alaz is able to gather more detailed information on containers running on nodes.
- log directory of the container,
- information related to its sandbox,
- pid,
- cgroups
- environment variables
- ...

> At time of today(23th August 2023). We do not take into consideration container runtimes data, we do not need it for todays objectives. Will be used later on for collecting more detailed data.

##### #  	2) Ebpf Programs
In Alaz's ebpf directory there are a couple of **ebpf programs written in C using libbpf**.

In order to compile these programs, we have a **ebpf-builder image** that contains necessary dependencies installed like **clang,llvm,libbpf and go**.

eBPF programs are compiled in mentioned container, leveraging ciliums bpf2go package. `github.com/cilium/ebpf/cmd/bpf2go`.

Using go generate directive with bpf2go, it compiles the eBPF program and generated necessary helper files in go in order us to interact with ebpf programs. 

- Link the program to a tracepoint or a kprobe. 
- Read bpf maps from user space and pass them for sense-making of data.

Used packages from cilium are :
 - `github.com/cilium/ebpf/link`
 - `github.com/cilium/ebpf/perf`
 - `github.com/cilium/ebpf/rlimit`

 ebpf programs: 
 - `tcp_state` : Detects newly established, closed, and listened TCP connections. The number of sockets associated with the program's PID depends on the remote IP address. Keeping this data together with the file descriptor is useful.
 - `l7_req` : Monitors both incoming and outgoing payloads by tracking the write and read syscalls. Then use `tcp_state` to aggregate the data we receive, allowing us to determine who sent which request to where.
 
Current  programs are generally attached to kernel tracepoints like:
 - tracepoint/syscalls/sys_enter_write (l7_req)
 - tracepoint/syscalls/sys_exit_write (l7_req)
 - tracepoint/syscalls/sys_enter_sendto (l7_req)
 - tracepoint/syscalls/sys_exit_sendto (l7_req)
 - tracepoint/syscalls/sys_enter_read (l7_req)
 - tracepoint/syscalls/sys_exit_read (l7_req)
 - tracepoint/syscalls/sys_enter_recvfrom (l7_req)
 - tracepoint/syscalls/sys_exit_recvfrom (l7_req)
 - tracepoint/sock/inet_sock_set_state (tcp_state)
 - tracepoint/syscalls/sys_enter_connect (tcp_state)
 - tracepoint/syscalls/sys_exit_connect (tcp_state)

#### How to Build Alaz
Alaz embeds compiled eBPF programs in it. After compilation process on ebpf-builder is done, compiled programs are located in project structure.

Using **//go:embed** directive of golang. We embed *.o* files and load them into kernel using `github.com/cilium/ebpf` package.

Then we build Alaz like a ordinary golang app more or less since compiled codes are embedded.

#### How to Deploy Alaz
Deployed as a privileged DaemonSet resource on the cluster.

Alaz is required to run as a privileged container since it needs read access to `/proc` directory of the host machine.

In order to link ebpf programs into kernel SYS_ADMIN and SYS_RESOURCE capabilities are required. For kernels 5.8+ BPF capability can be used instead of SYS_ADMIN. Since privileged container have all capabilties, we do not declare them explicitly.

If we are going to use containerd, we must mount related sock path:
 `			- mountPath: /var/run/containerd/containerd.sock
            name: containerd-sock
            readOnly: true
			`
			
And Alaz's `serviceAccount` must be should be associated with `ClusterRole` and `ClusterRoleBinding` resources in order to be able to talk with k8s server.





