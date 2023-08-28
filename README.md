# Alaz - Ddosify eBPF Agent

<h1 align="center">
    <img src="https://imagedelivery.net/jnIqn6NB1gbMLXIvlYKo5A/172d2843-4868-40e9-1bb0-1176d477d600/public" alt="Alaz Ddosify Usage" width="777px" /><br />
</h1>
<p align="center">
    <a href="https://github.com/ddosify/alaz/releases" target="_blank"><img src="https://img.shields.io/github/v/release/ddosify/alaz?style=for-the-badge&logo=github&color=orange" alt="alaz latest version" /></a>&nbsp;
    <a href="https://pkg.go.dev/go.ddosify.com/ddosify" target="_blank"><img src="https://img.shields.io/github/go-mod/go-version/ddosify/alaz?style=for-the-badge&logo=go" alt="alaz golang version" /></a>&nbsp;
    <a href="https://app.codecov.io/gh/ddosify/alaz" target="_blank"><img src="https://img.shields.io/codecov/c/github/ddosify/alaz?style=for-the-badge&logo=codecov" alt="go coverage" /></a>&nbsp;
    <a href="https://goreportcard.com/report/github.com/ddosify/alaz" target="_blank"><img src="https://goreportcard.com/badge/github.com/ddosify/alaz?style=for-the-badge&logo=go" alt="go report" /></a>&nbsp;
    <a href="https://github.com/ddosify/alaz/blob/master/LICENSE" target="_blank"><img src="https://img.shields.io/badge/LICENSE-AGPL--3.0-orange?style=for-the-badge&logo=none" alt="alaz license" /></a>
    <a href="https://discord.gg/9KdnrSUZQg" target="_blank"><img src="https://img.shields.io/discord/898523141788287017?style=for-the-badge&logo=discord&label=DISCORD" alt="ddosify discord server" /></a>
    <a href="https://hub.docker.com/r/ddosify/alaz" target="_blank"><img src="https://img.shields.io/docker/v/ddosify/alaz?style=for-the-badge&logo=docker&label=docker&sort=semver" alt="alaz docker image" /></a>
</p>


Alaz is an open-source Ddosify eBPF agent that can inspect and collect Kubernetes (K8s) service traffic without the need for code instrumentation, sidecars, or service restarts. This is possible due to its use of eBPF technology. Alaz can create a Service Map that helps identify golden signals and problems like high latencies, 5xx errors, zombie services, SQL queries. Additionally, it can gather system information and resources via the Prometheus Node Exporter, which is readily available on the agent. Alaz Docker image is available on [Docker Hub](https://hub.docker.com/r/ddosify/alaz).

➡️ For more information about Ddosify, see [Ddosify](https://github.com/ddosify/ddosify).

## Features

- ✅ Inspect and collect K8s service traffic without the need for code instrumentation, sidecars, or service restarts.
- ✅ Create a Service Map that helps identify golden signals and problems like high latencies, 5xx errors, zombie services.
- ✅ Gather system information and resources via the Prometheus Node Exporter, which is readily available on the agent.
- ✅ Works on both Arm64 and x86_64 architectures.
- ✅ Prometheus compatible metrics.
- ✅ Ddosify Cloud and Ddosify Self Hosted (On-Premise) support.

## Getting Started

To use Alaz, you need to have a [Ddosify Cloud](https://app.ddosify.com/register) account or [Ddosify Self Hosted](https://github.com/ddosify/ddosify/tree/master/selfhosted) installed. 

### For Ddosify Cloud

1. Register for a [Ddosify Cloud account](https://app.ddosify.com/register).
2. Add a cluster on the [Monitoring page](https://app.ddosify.com/monitoring). You will receive a monitoring ID and instructions.
3. Run the agent on your Kubernetes cluster using the instructions you received. There are two options for Kubernetes deployment: 

#### Using the kubectl

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
curl -sSL https://raw.githubusercontent.com/ddosify/alaz/master/resources/alaz.yaml
sed -i "" "s/<MONITORING_ID>/$MONITORING_ID/g" alaz.yaml
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
helm upgrade --install --namespace ddosify alaz ddosify/alaz --set daemonSet.container.env.MONITORING_ID=$MONITORING_ID
```

### For Ddosify Self Hosted

1. Install [Ddosify Self Hosted](https://github.com/ddosify/ddosify/tree/master/selfhosted)
2. Add a cluster on the [Monitoring page](http://localhost:8014/monitoring). You will receive a monitoring ID and instructions.
2. Run the agent on your Kubernetes cluster using the instructions you received. There are two options for Kubernetes deployment:


#### Using the kubectl

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
# Replace <BACKEND_HOST> with your backend host for Ddosify Self Hosted. Change XXXXX with your backend host.
BACKEND_HOST=XXXXX
curl -sSL https://raw.githubusercontent.com/ddosify/alaz/master/resources/alaz.yaml
sed -i "" "s/<MONITORING_ID>/$MONITORING_ID/g" alaz.yaml
sed -i "" "s/https://api.ddosify.com:443/$BACKEND_HOST/g" alaz.yaml
kubectl create namespace ddosify
kubectl apply -f alaz.yaml
```

#### Using the Helm

```bash
# Replace <MONITORING_ID> with your monitoring ID from the Ddosify Cloud. Change XXXXX with your monitoring ID.
MONITORING_ID=XXXXX
# Replace <BACKEND_HOST> with your backend host for Ddosify Self Hosted. Change XXXXX with your backend host. Backend host should be accessible from the Kubernetes cluster.
BACKEND_HOST=XXXXX
helm repo add ddosify https://ddosify.github.io/ddosify-helm-charts/
helm repo update
kubectl create namespace ddosify
helm upgrade --install --namespace ddosify alaz ddosify/alaz --set monitoringID=$MONITORING_ID --set backendHost=$BACKEND_HOST
```

Alaz runs as a DaemonSet on your Kubernetes cluster. It collects metrics and sends them to Ddosify Cloud or Ddosify Self Hosted. You can view the metrics on the Ddosify Observability dashboard. For the detailed Alaz architecture, see [Alaz Architecture](./Alaz-Architecture.md).

## Limitations

Alaz is currently only available for Linux Kubernetes clusters. It does not support Windows or MacOS. In the future, we plan to support Docker containers. 

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
