
<h1 align="center">Alaz - Ddosify eBPF Agent for Kubernetes Monitoring</h1>

<p align="center">
    <a href="https://github.com/ddosify/alaz/blob/master/LICENSE" target="_blank"><img src="https://img.shields.io/badge/LICENSE-AGPL--3.0-orange?style=for-the-badge&logo=none" alt="alaz license" /></a>
    <a href="https://discord.gg/9KdnrSUZQg" target="_blank"><img src="https://img.shields.io/discord/898523141788287017?style=for-the-badge&logo=discord&label=DISCORD" alt="ddosify discord server" /></a>
    <a href="https://hub.docker.com/r/ddosify/alaz" target="_blank"><img src="https://img.shields.io/docker/v/ddosify/alaz?style=for-the-badge&logo=docker&label=docker&sort=semver" alt="alaz docker image" /></a>
</p>

<p align="center">
<img src="https://raw.githubusercontent.com/ddosify/alaz/master/assets/ddosify_service_map.png" alt="Ddosify Kubernetes Monitoring Service Map" />
<i>Ddosify automatically generates Service Map of your K8s cluster without code instrumentation or sidecars with eBPF Agent Alaz. So you can easily find the bottlenecks in your system. Red lines indicate the high latency between services.</i>
</p>

<h2 align="center">
    <a href="https://demo.ddosify.com/" target="_blank">Live Demo</a> •
    <a href="https://docs.ddosify.com/" target="_blank">Documentation</a> •
    <a href="https://docs.ddosify.com/ddosify/deployment" target="_blank">Deployment</a> •
    <a href="https://docs.ddosify.com/ddosify/deployment" target="_blank">Discord</a>
</h2>


## What is Alaz?

[Alaz](https://github.com/ddosify/alaz) is an open-source Ddosify eBPF agent that can inspect and collect Kubernetes (K8s) service traffic without the need for code instrumentation, sidecars, or service restarts. This is possible due to its use of eBPF technology. 

Alaz can create a **Service Map** that helps identify golden signals and problems like:
- High latencies between K8s services
- Detect 5xx HTTP status codes 
- Detect Idle / Zombie services
- Detect slow SQL queries

Additionally, Ddosify tracks and displays live data on your cluster instances CPU, memory, disk, and network usage. All of the dashboards are generated out-of-box and you can create alerts based on these metrics values. Check out the [docs](https://docs.ddosify.com/) for more. 

<p align="center">
<img src="https://raw.githubusercontent.com/ddosify/alaz/master/assets/ddosify_metrics.png" alt="Ddosify Kubernetes Monitoring Metrics" />
<i>Ddosify tracks and displays live data on your cluster instances CPU, memory, disk, and network usage.</i>
</p>


➡️ For more information about Ddosify, see [Ddosify](https://github.com/ddosify/ddosify).

## Features

✅ **Low-Overhead:** 

Inspect and collect K8s service traffic without the need for code instrumentation, sidecars, or service restarts.

✅ **Effortless:** 

Ddosify will create the Service Map & Metrics Dashboard that helps identify golden signals and issues such as high latencies, 5xx errors, zombie services.

✅ **Prometheus Compatible:** 

Gather system information and resources via the Prometheus Node Exporter, which is readily available on the agent.

✅ **Cloud or On-premise:** 

Export metrics to [Ddosify Cloud](https://ddosify.com), or install the [Ddosify Self-Hosted](https://github.com/ddosify/ddosify/tree/master/selfhosted) in your infrastructure and manage everything according to your needs.

✅ **Test & Observe:** 

Ddosify Performance Testing and Alaz can work collaboratively. You can start a load test and monitor your system simultaneously. This will help you spot performance issues instantly. Check out the [Ddosify GitHub Repository](https://github.com/ddosify/ddosify) for more information about Ddosify Stack.

✅ **Alerts for Anomalies:** If something unusual, like a sudden increase in CPU usage, happens in your Kubernetes (K8s) cluster, Ddosify immediately sends alerts to your Slack.

✅ Works on both Arm64 and x86_64 architectures.

## Getting Started

To use Alaz, you need to have a [Ddosify Cloud](https://app.ddosify.com/register) account or [Ddosify Self-Hosted](https://github.com/ddosify/ddosify/tree/master/selfhosted) installed. 

### ☁️ For Ddosify Cloud

1. Register for a [Ddosify Cloud account](https://app.ddosify.com/register).
2. Add a cluster on the [Observability page](https://app.ddosify.com/clusters). You will receive a Monitoring ID and instructions.
3. Run the agent on your Kubernetes cluster using the instructions you received. There are two options for Kubernetes deployment: 

#### Using the kubectl

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
curl -sSL https://raw.githubusercontent.com/ddosify/alaz/master/resources/alaz.yaml -o alaz.yaml
sed -i"" -e "s/<MONITORING_ID>/$MONITORING_ID/g" alaz.yaml
kubectl create namespace ddosify
kubectl apply -f alaz.yaml
```

#### Using the Helm

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
helm repo add ddosify https://ddosify.github.io/ddosify-helm-charts/
helm repo update
kubectl create namespace ddosify
helm upgrade --install --namespace ddosify alaz ddosify/alaz --set monitoringID=$MONITORING_ID
```

Then you can view the metrics and Kubernetes Service Map on the [Ddosify Observability dashboard](https://app.ddosify.com/clusters). For more information, see [Ddosify Kubernetes Monitoring](https://docs.ddosify.com/ddosify/kubernetes-monitoring).

### 🏠 For Ddosify Self-Hosted

1. Install [Ddosify Self-Hosted](https://github.com/ddosify/ddosify/tree/master/selfhosted)
2. Add a cluster on the Observability page of your Self-Hosted frontend. You will receive a Monitoring ID and instructions.
3. Run the agent on your Kubernetes cluster using the instructions you received. 

Note: After you install Ddosify Self-Hosted, you will have a Ddosify Self-Hosted endpoint of nginx reverse proxy. The base URL of the Ddosify Self-Hosted endpoint forwards traffic to the frontend. The base URL of the Ddosify Self-Hosted endpoint with `/api` suffix forwards traffic to the backend. So you need to set the backend host variable as `http://<your-ddosify-self-hosted-endpoint>/api`.

There are two options for Kubernetes deployment:

#### Using the kubectl

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
# Set BACKEND_HOST with your Ddosify Self Hosted Endpoint. If your Ddosify Self Hosted endpoint is http://localhost:8014, then BACKEND_HOST=localhost:8014
BACKEND_HOST=XXXXX
curl -sSL https://raw.githubusercontent.com/ddosify/alaz/master/resources/alaz.yaml -o alaz.yaml
sed -i"" -e "s/<MONITORING_ID>/$MONITORING_ID/g" alaz.yaml
sed -i"" -e "s/https:\/\/api.ddosify.com:443/http:\/\/$BACKEND_HOST\/api/g" alaz.yaml
kubectl create namespace ddosify
kubectl apply -f alaz.yaml
```

#### Using the Helm

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
# Set BACKEND_HOST with your Ddosify Self Hosted Endpoint. If your Ddosify Self Hosted endpoint is http://localhost:8014, then BACKEND_HOST=http://localhost:8014/api
BACKEND_HOST=XXXXX
helm repo add ddosify https://ddosify.github.io/ddosify-helm-charts/
helm repo update
kubectl create namespace ddosify
helm upgrade --install --namespace ddosify alaz ddosify/alaz --set monitoringID=$MONITORING_ID --set backendHost=$BACKEND_HOST
```

Then you can view the metrics and Kubernetes Service Map on the Ddosify Self-Hosted Observability dashboard. For more information, see [Ddosify Monitoring Docs](https://docs.ddosify.com/ddosify/kubernetes-monitoring).

Alaz runs as a DaemonSet on your Kubernetes cluster. It collects metrics and sends them to Ddosify Cloud or Ddosify Self-Hosted. You can view the metrics on the Ddosify Observability dashboard. For the detailed Alaz architecture, see [Alaz Architecture](https://github.com/ddosify/alaz/blob/master/Alaz-Architecture.md).

## Cleanup

To remove Alaz from your Kubernetes cluster, run the following command:

- For Kubectl

```bash
kubectl delete -f https://raw.githubusercontent.com/ddosify/alaz/master/resources/alaz.yaml
```

- For Helm

```bash
helm delete alaz --namespace ddosify
```

## Supported Protocols

Alaz supports the following protocols:

- HTTP
- HTTPS (OpenSSL and Go TLS)
- HTTP2
- Postgres
- RabbitMQ
- gRPC

Other protocols will be supported soon.

## Limitations

Alaz runs on Linux Kubernetes clusters. Windows or MacOS are not supported.
In the future, we plan to support Docker containers.

Alaz is an eBPF application that uses [CO-RE](https://github.com/libbpf/libbpf#bpf-co-re-compile-once--run-everywhere).
Most of the latest linux distributions support CO-RE. In order to CO-RE to work, the kernel has to built with BTF(bpf type format) information.

You can check your kernel version with `uname -r` 
command and whether btf is enabled by default or not at the [btfhub](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md).

For the time being, we expect that btf information is readily available on your system. We'll support all kernels in the upcoming weeks leveraging [btfhub](https://github.com/aquasecurity/btfhub).

#### Encryption Libraries
These are the libraries that alaz hooks into for capturing encrypted traffic.
- [crypto/tls](https://pkg.go.dev/crypto/tls):
In order to Alaz to capture tls requests in your Go applications, your go version must be **1.17+** and your executable must include debug info.

- [OpenSSL](https://www.openssl.org/):
OpenSSL shared objects that is dynamically linked into your executable is supported.
Supported versions : **1.0.2**, **1.1.1** and **3.***

## Contributing

Contributions to Alaz are welcome! To contribute, please follow these steps:

1. Fork the repository
2. Create a new branch: `git checkout -b my-branch`
3. Make your changes and commit them: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-branch`
5. Submit a pull request

## Communication

You can join our [Discord Server](https://discord.gg/9KdnrSUZQg) for issues, feature requests, feedbacks or anything else. 

## License

Alaz is licensed under the AGPLv3: https://www.gnu.org/licenses/agpl-3.0.html

