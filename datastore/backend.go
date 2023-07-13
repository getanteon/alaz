package datastore

import (
	"alaz/config"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/uuid"
)

var MonitoringID string

func init() {
	x := os.Getenv("MONITORING_ID")
	if x == "" {
		MonitoringID = string(uuid.NewUUID())
	} else {
		MonitoringID = x
	}
}

type PodPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	IP        string `json:"ip"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type SvcPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID        string   `json:"uid"`
	EventType  string   `json:"event_type"`
	Name       string   `json:"name"`
	Namespace  string   `json:"namespace"`
	Type       string   `json:"type"`
	ClusterIPs []string `json:"cluster_ips"`
	Ports      []struct {
		Src      int32  `json:"src"`
		Dest     int32  `json:"dest"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

type ReplicaSetPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
	OwnerType string `json:"owner_type"`
	OwnerName string `json:"owner_name"`
	OwnerID   string `json:"owner_id"`
}

type DeploymentPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Replicas  int32  `json:"replicas"`
}

type EndpointsPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string    `json:"uid"`
	EventType string    `json:"event_type"`
	Name      string    `json:"name"`
	Namespace string    `json:"namespace"`
	Service   string    `json:"service"`
	Addresses []Address `json:"addresses"`
}

type ContainerPayload struct {
	Metadata struct {
		MonitoringID   string `json:"monitoring_id"`
		IdempotencyKey string `json:"idempotency_key"`
	} `json:"metadata"`
	UID       string `json:"uid"`
	EventType string `json:"event_type"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Image     string `json:"image"`
	Ports     []struct {
		Port     int32  `json:"port"`
		Protocol string `json:"protocol"`
	} `json:"ports"`
}

// BackendDS is a backend datastore
type BackendDS struct {
	host  string
	port  string
	token string
	c     *http.Client
}

const (
	podEndpoint       = "/alaz/k8s/pod/"
	svcEndpoint       = "/alaz/k8s/svc/"
	rsEndpoint        = "/alaz/k8s/replicaset/"
	depEndpoint       = "/alaz/k8s/deployment/"
	epEndpoint        = "/alaz/k8s/endpoint/"
	containerEndpoint = "/alaz/k8s/container/"
)

func NewBackendDS(conf config.BackendConfig) *BackendDS {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: false,
			MaxConnsPerHost:   100, // 100 connection per host
		},
		Timeout: 5 * time.Second, // Set a timeout for the request
		// CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// 	return http.ErrUseLastResponse
		// },
	}

	return &BackendDS{
		host:  conf.Host,
		port:  conf.Port,
		token: conf.Token,
		c:     client,
	}
}

func (b *BackendDS) DoRequest(req *http.Request) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// TODO: add retry logic here

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.token))

	resp, err := b.c.Do(req)
	if err != nil {
		return fmt.Errorf("error sending http request: %v", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body) // in order to reuse the connection
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("not success: %d, %s", resp.StatusCode, string(body))
	}

	return nil
}

func convertPodToPayload(pod Pod, eventType string) PodPayload {
	return PodPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{
			MonitoringID:   MonitoringID,
			IdempotencyKey: string(uuid.NewUUID()),
		},
		UID:       pod.UID,
		EventType: eventType,
		Name:      pod.Name,
		Namespace: pod.Namespace,
		IP:        pod.IP,
		OwnerType: pod.OwnerType,
		OwnerName: pod.OwnerName,
		OwnerID:   pod.OwnerID,
	}
}

func (b *BackendDS) PersistPod(pod Pod, eventType string) error {
	podPayload := convertPodToPayload(pod, eventType)

	c, err := json.Marshal(podPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+podEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func convertSvcToPayload(service Service, eventType string) SvcPayload {
	return SvcPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{
			MonitoringID:   MonitoringID,
			IdempotencyKey: string(uuid.NewUUID()),
		},
		UID:        service.UID,
		EventType:  "ADD",
		Name:       service.Name,
		Namespace:  service.Namespace,
		Type:       service.Type,
		ClusterIPs: service.ClusterIPs,
		Ports:      service.Ports,
	}
}

func (b *BackendDS) PersistService(service Service, eventType string) error {
	svcPayload := convertSvcToPayload(service, eventType)

	c, err := json.Marshal(svcPayload)
	if err != nil {
		return fmt.Errorf("error marshalling svc payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+svcEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func convertReplicasetToPayload(rs ReplicaSet, eventType string) ReplicaSetPayload {
	return ReplicaSetPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{MonitoringID: MonitoringID, IdempotencyKey: string(uuid.NewUUID())},
		UID:       rs.UID,
		EventType: eventType,
		Name:      rs.Name,
		Namespace: rs.Namespace,
		Replicas:  rs.Replicas,
		OwnerType: rs.OwnerType,
		OwnerName: rs.OwnerName,
		OwnerID:   rs.OwnerID,
	}
}

func (b *BackendDS) PersistReplicaSet(rs ReplicaSet, eventType string) error {
	rsPayload := convertReplicasetToPayload(rs, eventType)

	c, err := json.Marshal(rsPayload)
	if err != nil {
		return fmt.Errorf("error marshalling rs payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+rsEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func convertDeploymentToPayload(d Deployment, eventType string) DeploymentPayload {
	return DeploymentPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{MonitoringID: MonitoringID, IdempotencyKey: string(uuid.NewUUID())},
		UID:       d.UID,
		EventType: eventType,
		Name:      d.Name,
		Namespace: d.Namespace,
		Replicas:  d.Replicas,
	}
}

func convertEndpointsToPayload(ep Endpoints, eventType string) EndpointsPayload {
	return EndpointsPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{MonitoringID: MonitoringID, IdempotencyKey: string(uuid.NewUUID())},
		UID:       ep.UID,
		EventType: eventType,
		Name:      ep.Name,
		Namespace: ep.Namespace,
		Service:   ep.Service,
		Addresses: ep.Addresses,
	}
}

func convertContainerToPayload(c Container, eventType string) ContainerPayload {
	return ContainerPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{MonitoringID: MonitoringID, IdempotencyKey: string(uuid.NewUUID())},
		UID:       c.UID,
		EventType: eventType,
		Name:      c.Name,
		Namespace: c.Namespace,
		Pod:       podEndpoint,
		Image:     c.Image,
		Ports:     c.Ports,
	}
}

func (b *BackendDS) PersistDeployment(d Deployment, eventType string) error {
	dPayload := convertDeploymentToPayload(d, eventType)

	c, err := json.Marshal(dPayload)
	if err != nil {
		return fmt.Errorf("error marshalling deployment payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+depEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) PersistEndpoints(ep Endpoints, eventType string) error {
	dPayload := convertEndpointsToPayload(ep, eventType)

	c, err := json.Marshal(dPayload)
	if err != nil {
		return fmt.Errorf("error marshalling endpoints payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+epEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) PersistContainer(c Container, eventType string) error {
	cPayload := convertContainerToPayload(c, eventType)

	bc, err := json.Marshal(cPayload)
	if err != nil {
		return fmt.Errorf("error marshalling container payload: %v", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+containerEndpoint, bytes.NewBuffer(bc))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) PersistRequest(request Request) error {
	// TODO: implement
	// save requests for batch sending for a period of time
	// then send in batches
	return nil
}
