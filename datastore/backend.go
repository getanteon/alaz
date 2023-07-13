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

// BackendDS is a backend datastore
type BackendDS struct {
	host  string
	port  string
	token string
	c     *http.Client
}

const (
	podEndpoint = "/alaz/k8s/pod"
	svcEndpoint = "/alaz/k8s/svc"
)

func NewBackendDS(conf config.BackendConfig) *BackendDS {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: false,
			MaxConnsPerHost:   100, // 100 connection per host
		},
		Timeout: 5 * time.Second, // Set a timeout for the request
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
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // in order to reuse the connection

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("not success: %d", resp.StatusCode)
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

func (b *BackendDS) CreatePod(pod Pod) error {
	podPayload := convertPodToPayload(pod, "ADD")

	c, err := json.Marshal(podPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+podEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) UpdatePod(pod Pod) error {
	podPayload := convertPodToPayload(pod, "UPDATE")

	c, err := json.Marshal(podPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+podEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) DeletePod(pod Pod) error {
	podPayload := convertPodToPayload(pod, "DELETE")

	c, err := json.Marshal(podPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+podEndpoint, bytes.NewBuffer(c))
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

func (b *BackendDS) CreateService(service Service) error {
	svcPayload := convertSvcToPayload(service, "ADD")

	c, err := json.Marshal(svcPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+svcEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) UpdateService(service Service) error {
	svcPayload := convertSvcToPayload(service, "UPDATE")

	c, err := json.Marshal(svcPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+svcEndpoint, bytes.NewBuffer(c))
	if err != nil {
		return fmt.Errorf("error creating http request: %v", err)
	}

	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) DeleteService(service Service) error {
	svcPayload := convertSvcToPayload(service, "DELETE")

	c, err := json.Marshal(svcPayload)
	if err != nil {
		return fmt.Errorf("error marshalling pod payload: %v", err)
	}

	httpReq, err := http.NewRequest("POST", b.host+":"+b.port+svcEndpoint, bytes.NewBuffer(c))
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
