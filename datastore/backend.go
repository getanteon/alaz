package datastore

import (
	"alaz/config"
	"alaz/log"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/go-retryablehttp"

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

// BackendDS is a backend datastore
type BackendDS struct {
	host      string
	port      string
	token     string
	c         *http.Client
	batchSize int64

	reqChanBuffer chan *ReqInfo
}

const (
	podEndpoint       = "/alaz/k8s/pod/"
	svcEndpoint       = "/alaz/k8s/svc/"
	rsEndpoint        = "/alaz/k8s/replicaset/"
	depEndpoint       = "/alaz/k8s/deployment/"
	epEndpoint        = "/alaz/k8s/endpoint/"
	containerEndpoint = "/alaz/k8s/container/"
	reqEndpoint       = "/alaz/"
)

func NewBackendDS(conf config.BackendConfig) *BackendDS {
	retryClient := retryablehttp.NewClient()
	retryClient.Backoff = retryablehttp.DefaultBackoff
	retryClient.RetryWaitMin = 1 * time.Second
	retryClient.RetryWaitMax = 5 * time.Second
	retryClient.RetryMax = 4

	retryClient.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		var shouldRetry bool
		if err != nil { // resp, (doErr) = c.HTTPClient.Do(req.Request)
			// connection refused, connection reset, connection timeout
			shouldRetry = true
			log.Logger.Warn().Msgf("will retry, error: %v", err)

			rb, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Logger.Warn().Msgf("error reading response body: %v", err)
			}
			log.Logger.Warn().Msgf("will retry, response body: %s", string(rb))

		} else {
			if resp.StatusCode == http.StatusBadRequest ||
				resp.StatusCode == http.StatusTooManyRequests ||
				resp.StatusCode >= http.StatusInternalServerError {
				shouldRetry = true

				rb, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Logger.Warn().Msgf("error reading response body: %v", err)
				}
				log.Logger.Warn().Msgf("will retry, response body: %s", string(rb))
				log.Logger.Warn().Msgf("will retry, status code: %d", resp.StatusCode)

			}
		}
		return shouldRetry, nil
	}

	retryClient.HTTPClient.Transport = &http.Transport{
		DisableKeepAlives: false,
		MaxConnsPerHost:   500, // 500 connection per host
	}
	retryClient.HTTPClient.Timeout = 10 * time.Second // Set a timeout for the request
	client := retryClient.StandardClient()

	var defaultBatchSize int64 = 1000

	bs, err := strconv.ParseInt(os.Getenv("BATCH_SIZE"), 10, 64)
	if err != nil {
		bs = defaultBatchSize
	}

	ds := &BackendDS{
		host:          conf.Host,
		port:          conf.Port,
		token:         conf.Token,
		c:             client,
		reqChanBuffer: make(chan *ReqInfo, 10000),
		batchSize:     bs,
	}

	go ds.sendReqsInBatch()

	return ds
}

func (b *BackendDS) DoRequest(req *http.Request) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", b.token))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := b.c.Do(req.WithContext(ctx))
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
	} else {
		log.Logger.Info().Msg("success")
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

	log.Logger.Info().Msg("sending pod to backend")
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

	log.Logger.Info().Msg("sending service to backend")
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

	log.Logger.Info().Msg("sending replicaset to backend")
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
		Pod:       c.PodUID,
		Image:     c.Image,
		Ports:     c.Ports,
	}
}

func convertReqsToPayload(batch []*ReqInfo) RequestsPayload {
	return RequestsPayload{
		Metadata: struct {
			MonitoringID   string `json:"monitoring_id"`
			IdempotencyKey string `json:"idempotency_key"`
		}{MonitoringID: MonitoringID, IdempotencyKey: string(uuid.NewUUID())},
		Requests: batch,
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

	log.Logger.Info().Msg("sending deployment to backend")
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

	log.Logger.Info().Msg("sending endpoints to backend")
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

	log.Logger.Info().Msg("sending container to backend")
	err = b.DoRequest(httpReq)
	if err != nil {
		return fmt.Errorf("error on persisting to backend: %v", err)
	}

	return nil
}

func (b *BackendDS) sendReqsInBatch() {

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			b.sendBatch()
			// case <-b.stopChan: // TODO
			// 	return
		}
	}

}

func (b *BackendDS) sendBatch() {
	batch := make([]*ReqInfo, 0, b.batchSize)
	loop := true

	for i := 0; (i < int(b.batchSize)) && loop; i++ {
		select {
		case req := <-b.reqChanBuffer:
			batch = append(batch, req)
		case <-time.After(1 * time.Second):
			loop = false
		}
	}

	if len(batch) == 0 {
		return
	}

	reqsPayload := convertReqsToPayload(batch)

	reqsBytes, err := json.Marshal(reqsPayload)
	if err != nil {
		log.Logger.Error().Msgf("error marshalling batch: %v", err)
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+reqEndpoint, bytes.NewBuffer(reqsBytes))
	if err != nil {
		log.Logger.Error().Msgf("error creating http request: %v", err)
		return
	}

	log.Logger.Info().Msg("sending batch to backend")
	err = b.DoRequest(httpReq)
	if err != nil {
		log.Logger.Error().Msgf("error on persisting requests to backend: %v", err)
	}

}

func (b *BackendDS) PersistRequest(request Request) error {
	reqInfo := &ReqInfo{}
	reqInfo[0] = request.StartTime
	reqInfo[1] = request.Latency
	reqInfo[2] = request.FromIP
	reqInfo[3] = request.FromType
	reqInfo[4] = request.FromUID
	reqInfo[5] = request.FromPort
	reqInfo[6] = request.ToIP
	reqInfo[7] = request.ToType
	reqInfo[8] = request.ToUID
	reqInfo[9] = request.ToPort
	reqInfo[10] = request.Protocol
	reqInfo[11] = request.StatusCode
	reqInfo[12] = request.FailReason // TODO ??
	reqInfo[13] = request.Method
	reqInfo[14] = request.Path

	b.reqChanBuffer <- reqInfo

	return nil
}
