package k8s

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ddosify/alaz/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	appsv1 "k8s.io/client-go/informers/apps/v1"
	v1 "k8s.io/client-go/informers/core/v1"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

type K8SResourceType string

const (
	SERVICE    = "Service"
	POD        = "Pod"
	REPLICASET = "ReplicaSet"
	DEPLOYMENT = "Deployment"
	ENDPOINTS  = "Endpoints"
	CONTAINER  = "Container"
	DAEMONSET  = "DaemonSet"
)

const (
	ADD    = "Add"
	UPDATE = "Update"
	DELETE = "Delete"
)

var k8sVersion string
var resyncPeriod time.Duration = 120 * time.Second

type K8sCollector struct {
	ctx              context.Context
	informersFactory informers.SharedInformerFactory
	watchers         map[K8SResourceType]cache.SharedIndexInformer
	clientset        *kubernetes.Clientset
	stopper          chan struct{} // stop signal for the informers
	doneChan         chan struct{} // done signal for k8sCollector
	// watchers
	podInformer        v1.PodInformer
	serviceInformer    v1.ServiceInformer
	replicasetInformer appsv1.ReplicaSetInformer
	deploymentInformer appsv1.DeploymentInformer
	endpointsInformer  v1.EndpointsInformer
	daemonsetInformer  appsv1.DaemonSetInformer

	Events chan interface{}
}

var nodeName string

func init() {
	nodeName = os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Logger.Fatal().Msg("NODE_NAME is not set")
	}
}
func (k *K8sCollector) Init(events chan interface{}) error {
	log.Logger.Info().Msg("k8sCollector initializing...")
	k.Events = events

	// Pod
	k.podInformer = k.informersFactory.Core().V1().Pods()
	k.watchers[POD] = k.podInformer.Informer()

	// Service
	k.serviceInformer = k.informersFactory.Core().V1().Services()
	k.watchers[SERVICE] = k.informersFactory.Core().V1().Services().Informer()

	// ReplicaSet
	k.replicasetInformer = k.informersFactory.Apps().V1().ReplicaSets()
	k.watchers[REPLICASET] = k.replicasetInformer.Informer()

	// Deployment
	k.deploymentInformer = k.informersFactory.Apps().V1().Deployments()
	k.watchers[DEPLOYMENT] = k.deploymentInformer.Informer()

	// Endpoints
	k.endpointsInformer = k.informersFactory.Core().V1().Endpoints()
	k.watchers[ENDPOINTS] = k.endpointsInformer.Informer()

	// DaemonSet
	k.daemonsetInformer = k.informersFactory.Apps().V1().DaemonSets()
	k.watchers[DAEMONSET] = k.daemonsetInformer.Informer()

	defer runtime.HandleCrash()

	// Add event handlers
	k.watchers[POD].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddPodFunc(k.Events),
		UpdateFunc: getOnUpdatePodFunc(k.Events),
		DeleteFunc: getOnDeletePodFunc(k.Events),
	})

	k.watchers[SERVICE].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddServiceFunc(k.Events),
		UpdateFunc: getOnUpdateServiceFunc(k.Events),
		DeleteFunc: getOnDeleteServiceFunc(k.Events),
	})

	k.watchers[REPLICASET].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddReplicaSetFunc(k.Events),
		UpdateFunc: getOnUpdateReplicaSetFunc(k.Events),
		DeleteFunc: getOnDeleteReplicaSetFunc(k.Events),
	})

	k.watchers[DEPLOYMENT].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddDeploymentSetFunc(k.Events),
		UpdateFunc: getOnUpdateDeploymentSetFunc(k.Events),
		DeleteFunc: getOnDeleteDeploymentSetFunc(k.Events),
	})

	k.watchers[ENDPOINTS].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddEndpointsSetFunc(k.Events),
		UpdateFunc: getOnUpdateEndpointsSetFunc(k.Events),
		DeleteFunc: getOnDeleteEndpointsSetFunc(k.Events),
	})

	k.watchers[DAEMONSET].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddDaemonSetFunc(k.Events),
		UpdateFunc: getOnUpdateDaemonSetFunc(k.Events),
		DeleteFunc: getOnDeleteDaemonSetFunc(k.Events),
	})

	wg := sync.WaitGroup{}
	wg.Add(len(k.watchers))
	for _, watcher := range k.watchers {
		go func(watcher cache.SharedIndexInformer) {
			watcher.Run(k.stopper) // it will return when stopper is closed
			wg.Done()
		}(watcher)
	}
	wg.Wait()
	log.Logger.Info().Msg("k8sCollector informers stopped")
	k.doneChan <- struct{}{}

	return nil
}

func (k *K8sCollector) Done() <-chan struct{} {
	return k.doneChan
}

var innerContainerMetricsPort int = 8184

func NewK8sCollector(parentCtx context.Context) (*K8sCollector, error) {
	ctx, _ := context.WithCancel(parentCtx)
	// get incluster kubeconfig
	var kubeconfig *string
	var kubeConfig *rest.Config

	if os.Getenv("IN_CLUSTER") == "false" {
		var err error
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}

		flag.Parse()

		kubeConfig, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err)
		}
	} else {
		// in cluster config, default
		var err error
		kubeConfig, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("unable to get incluster kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create clientset: %w", err)
	}

	version, err := clientset.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("unable to get k8s server version: %w", err)
	}

	k8sVersion = version.String()

	factory := informers.NewSharedInformerFactory(clientset, resyncPeriod)

	collector := &K8sCollector{
		ctx:              ctx,
		stopper:          make(chan struct{}),
		doneChan:         make(chan struct{}),
		informersFactory: factory,
		clientset:        clientset,
		watchers:         map[K8SResourceType]cache.SharedIndexInformer{},
	}

	go func(c *K8sCollector) {
		<-c.ctx.Done() // wait for context to be cancelled
		c.close()
	}(collector)

	return collector, nil
}

func (k *K8sCollector) ExportContainerMetrics() error {
	metricsPath := "/inner/container-metrics"
	http.Handle(metricsPath, k)
	go func() {
		err := http.ListenAndServe(fmt.Sprintf(":%d", innerContainerMetricsPort), nil)
		if err != nil {
			log.Logger.Error().Err(err).Msg("failed to start inner container metrics server")
		}
	}()
	// TODO: check health
	return nil
}

type FilteredReader struct {
	reader  io.Reader
	format  expfmt.Format
	decoder expfmt.Decoder

	buf *bytes.Buffer
}

func NewFilteredReader(r io.Reader) *FilteredReader {
	format := expfmt.NewFormat(expfmt.TypeProtoText)
	decoder := expfmt.NewDecoder(r, format)

	return &FilteredReader{
		reader:  r,
		format:  format,
		decoder: decoder,
		buf:     bytes.NewBuffer([]byte{}),
	}
}

func (f *FilteredReader) WriteTo(w io.Writer) (n int64, err error) {
	format := expfmt.NewFormat(expfmt.TypeTextPlain)
	decoder := expfmt.NewDecoder(f.reader, format)
	for {
		metric := &dto.MetricFamily{}
		err = decoder.Decode(metric)
		if err != nil {
			log.Logger.Info().Err(err).Msg("error decoding metric")
			return n, err
		}

		// log.Logger.Info().Msg(metric.GetName())
		// log.Logger.Info().Msgf("metric: %s, %s, %s, %s", metric.GetName(), metric.GetHelp(), metric.GetType(), metric.String())
		// TODO: filter metrics based on namespaces, labels, etc.

		// encode metric
		// write encoded metric to w
		escapingScheme := format.ToEscapingScheme()
		written, err := expfmt.MetricFamilyToText(w, model.EscapeMetricFamily(metric, escapingScheme))

		if err != nil {
			log.Logger.Info().Err(err).Msg("error encoding metric")
			return n, err
		} else {
			n += int64(written)
		}
	}
}

func (fw *FilteredReader) Read(p []byte) (n int, err error) {
	if fw.buf.Len() > 0 {
		// copy to p
		written := 0
		encodedBytes := fw.buf.Bytes()
		bufLen := fw.buf.Len()
		log.Logger.Info().Msgf("bufLen: %d", bufLen)
		for i := 0; i < bufLen; i++ {
			if i < len(p) {
				p[i] = encodedBytes[i]
				written++
			} else {
				// p is full
				break
			}
		}

		fw.buf = bytes.NewBuffer(encodedBytes[written:])
		return written, err
	}

	metric := &dto.MetricFamily{}
	err = fw.decoder.Decode(metric)
	if err != nil {
		fw.buf = bytes.NewBuffer([]byte{}) // Reset() keeps underlying buffer
		log.Logger.Info().Err(err).Msg("error decoding metric")
		return n, err
	}

	// log.Logger.Info().Msg(metric.GetName())
	// log.Logger.Info().Msgf("metric: %s, %s, %s, %s", metric.GetName(), metric.GetHelp(), metric.GetType(), metric.String())
	// TODO: filter metrics based on namespaces, labels, etc.

	// encode metric
	// write encoded metric to w

	escapingScheme := fw.format.ToEscapingScheme()
	nOwnBuffer, err := expfmt.MetricFamilyToText(fw.buf, model.EscapeMetricFamily(metric, escapingScheme))

	if err != nil {
		log.Logger.Info().Err(err).Msg("error encoding metric")
		return n, err
	}

	log.Logger.Info().Msgf("nOwnBuffer: %d", nOwnBuffer)

	// copy to p
	written := 0
	encodedBytes := fw.buf.Bytes()
	for i := 0; i < nOwnBuffer; i++ {
		if i < len(p) {
			p[i] = encodedBytes[i]
			written++
		} else {
			// p is full
			break
		}
	}

	// truncate buffer
	fw.buf = bytes.NewBuffer(encodedBytes[written:])
	return written, nil
}

// get container metrics from kubelet cadvisor in prometheus format
// return a reader for backend to stream metrics directly
func (k *K8sCollector) GetContainerMetrics(ctx context.Context) (io.Reader, error) {
	log.Logger.Debug().Msg("serving inner container metrics")
	// forward request to cadvisor
	// curl https://kubernetes.default.svc/api/v1/nodes/ip-192-168-68-164.eu-central-1.compute.internal/proxy/metrics/cadvisor --header "

	path := fmt.Sprintf("/api/v1/nodes/%s/proxy/metrics/cadvisor", nodeName)
	metrics, err := k.clientset.CoreV1().RESTClient().Get().Namespace("").AbsPath(path).Param("format", "text").Stream(ctx)

	if err != nil {
		return nil, fmt.Errorf("error getting kubelet cadvisor metrics request: %w", err)
	}

	// wrapper reader to filter out unwanted metrics
	filterReader := NewFilteredReader(metrics)

	return filterReader, nil
}

func (k *K8sCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Logger.Debug().Msg("serving inner container metrics")
	// forward request to cadvisor
	// curl https://kubernetes.default.svc/api/v1/nodes/ip-192-168-68-164.eu-central-1.compute.internal/proxy/metrics/cadvisor --header "

	metrics, err := k.GetContainerMetrics(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "error getting kubelet cadvisor metrics request: %v", err)
		return
	}

	// io.Copy will use WriteTo method of FilteredReader
	n, err := io.Copy(w, metrics)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Logger.Error().Err(err).Msg("error forwarding container metrics")
	} else if n == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		log.Logger.Error().Msg("could not write any bytes to response")
	}
}

func (k *K8sCollector) GetK8sVersion() string {
	return k8sVersion
}

func (k *K8sCollector) close() {
	log.Logger.Info().Msg("k8sCollector closing...")
	close(k.stopper) // stop informers
}

type K8sNamespaceResources struct {
	Pods     map[string]corev1.Pod     `json:"pods"`     // map[podName]Pod
	Services map[string]corev1.Service `json:"services"` // map[serviceName]Service
}

type K8sResourceMessage struct {
	ResourceType string      `json:"type"`
	EventType    string      `json:"eventType"`
	Object       interface{} `json:"object"`
}
