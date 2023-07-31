package datastore

import (
	"alaz/config"
	"alaz/log"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
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

var resourceBatchSize int64 = 50

// BackendDS is a backend datastore
type BackendDS struct {
	host      string
	port      string
	c         *http.Client
	batchSize int64

	reqChanBuffer chan *ReqInfo

	podEventChan       chan interface{} // *PodEvent
	svcEventChan       chan interface{} // *SvcEvent
	depEventChan       chan interface{} // *DepEvent
	rsEventChan        chan interface{} // *RsEvent
	epEventChan        chan interface{} // *EndpointsEvent
	containerEventChan chan interface{} // *ContainerEvent
	dsEventChan        chan interface{} // *DaemonSetEvent

	// TODO:
	// daemonset
	// statefulset
	// job
	// cronjob

}

const (
	podEndpoint       = "/alaz/k8s/pod/"
	svcEndpoint       = "/alaz/k8s/svc/"
	rsEndpoint        = "/alaz/k8s/replicaset/"
	depEndpoint       = "/alaz/k8s/deployment/"
	epEndpoint        = "/alaz/k8s/endpoint/"
	containerEndpoint = "/alaz/k8s/container/"
	dsEndpoint        = "/alaz/k8s/daemonset/"
	reqEndpoint       = "/alaz/"
)

func NewBackendDS(conf config.BackendConfig) *BackendDS {
	rand.Seed(time.Now().UnixNano())

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
			if resp != nil {
				rb, err := io.ReadAll(resp.Body)
				if err != nil {
					log.Logger.Warn().Msgf("error reading response body: %v", err)
				}
				log.Logger.Warn().Msgf("will retry, response body: %s", string(rb))
			}

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
		host:               conf.Host,
		port:               conf.Port,
		c:                  client,
		batchSize:          bs,
		reqChanBuffer:      make(chan *ReqInfo, 10000),
		podEventChan:       make(chan interface{}, 100),
		svcEventChan:       make(chan interface{}, 100),
		rsEventChan:        make(chan interface{}, 100),
		depEventChan:       make(chan interface{}, 50),
		epEventChan:        make(chan interface{}, 100),
		containerEventChan: make(chan interface{}, 100),
		dsEventChan:        make(chan interface{}, 20),
	}

	go ds.sendReqsInBatch()

	eventsInterval := 5 * time.Second
	go ds.sendEventsInBatch(ds.podEventChan, podEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.svcEventChan, svcEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.rsEventChan, rsEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.depEventChan, depEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.epEventChan, epEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.containerEventChan, containerEndpoint, eventsInterval)
	go ds.sendEventsInBatch(ds.dsEventChan, dsEndpoint, eventsInterval)

	return ds
}

func (b *BackendDS) DoRequest(req *http.Request) error {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

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
		log.Logger.Warn().Str("reqHostPath", req.URL.Host+req.URL.Path).Msg("success on request")
	}

	return nil
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

func (b *BackendDS) sendToBackend(payload interface{}, endpoint string) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Logger.Error().Msgf("error marshalling batch: %v", err)
		return
	}

	httpReq, err := http.NewRequest(http.MethodPost, b.host+":"+b.port+endpoint, bytes.NewBuffer(payloadBytes))
	if err != nil {
		log.Logger.Error().Msgf("error creating http request: %v", err)
		return
	}

	log.Logger.Warn().Str("endpoint", endpoint).Any("payload", payload).Msg("sending batch to backend")
	err = b.DoRequest(httpReq)
	if err != nil {
		log.Logger.Error().Msgf("backend persist error at ep %s : %v", endpoint, err)
	}
}

func (b *BackendDS) sendReqsInBatch() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	send := func() {
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
		b.sendToBackend(reqsPayload, reqEndpoint)
	}

	for {
		select {
		case <-t.C:
			send()
			// case <-b.stopChan: // TODO
			// 	return
		}
	}

}

func (b *BackendDS) send(ch <-chan interface{}, endpoint string) {
	batch := make([]interface{}, 0, resourceBatchSize)
	loop := true

	for i := 0; (i < int(resourceBatchSize)) && loop; i++ {
		select {
		case ev := <-ch:
			batch = append(batch, ev)
		case <-time.After(1 * time.Second):
			loop = false
		}
	}

	if len(batch) == 0 {
		return
	}

	payload := EventPayload{
		Metadata: struct {
			MonitoringID   string "json:\"monitoring_id\""
			IdempotencyKey string "json:\"idempotency_key\""
		}{
			MonitoringID:   MonitoringID,
			IdempotencyKey: string(uuid.NewUUID()),
		},
		Events: batch,
	}

	b.sendToBackend(payload, endpoint)
}

func (b *BackendDS) sendEventsInBatch(ch chan interface{}, endpoint string, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			randomDuration := time.Duration(rand.Intn(50)) * time.Millisecond
			time.Sleep(randomDuration)

			b.send(ch, endpoint)
			// case <-b.stopChan: // TODO
			// 	return
		}
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

func (b *BackendDS) PersistPod(pod Pod, eventType string) error {
	podEvent := convertPodToPodEvent(pod, eventType)
	b.podEventChan <- &podEvent
	return nil
}

func (b *BackendDS) PersistService(service Service, eventType string) error {
	svcEvent := convertSvcToSvcEvent(service, eventType)
	b.svcEventChan <- &svcEvent
	return nil
}

func (b *BackendDS) PersistDeployment(d Deployment, eventType string) error {
	depEvent := convertDepToDepEvent(d, eventType)
	b.depEventChan <- &depEvent
	return nil
}

func (b *BackendDS) PersistReplicaSet(rs ReplicaSet, eventType string) error {
	rsEvent := convertRsToRsEvent(rs, eventType)
	b.rsEventChan <- &rsEvent
	return nil
}

func (b *BackendDS) PersistEndpoints(ep Endpoints, eventType string) error {
	epEvent := convertEpToEpEvent(ep, eventType)
	b.epEventChan <- &epEvent
	return nil
}

func (b *BackendDS) PersistDaemonSet(ds DaemonSet, eventType string) error {
	dsEvent := convertDsToDsEvent(ds, eventType)
	b.dsEventChan <- &dsEvent
	return nil
}

func (b *BackendDS) PersistContainer(c Container, eventType string) error {
	cEvent := convertContainerToContainerEvent(c, eventType)
	b.containerEventChan <- &cEvent
	return nil
}
