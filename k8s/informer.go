package k8s

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"alaz/log"

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
)

type K8SResourceType string

const (
	SERVICE    = "Service"
	POD        = "Pod"
	REPLICASET = "ReplicaSet"
	DEPLOYMENT = "Deployment"
	ENDPOINTS  = "Endpoints"
	CONTAINER  = "Container"
)

const (
	ADD    = "Add"
	UPDATE = "Update"
	DELETE = "Delete"
)

type K8sCollector struct {
	informersFactory informers.SharedInformerFactory
	watchers         map[K8SResourceType]cache.SharedIndexInformer
	stopper          chan struct{} // stop signal for the informer
	// watchers
	podInformer        v1.PodInformer
	serviceInformer    v1.ServiceInformer
	replicasetInformer appsv1.ReplicaSetInformer
	deploymentInformer appsv1.DeploymentInformer
	endpointsInformer  v1.EndpointsInformer

	k8sBigPicture *K8sBigPicture
	Events        chan interface{}
}

func (k *K8sCollector) advertiseBigPicture() {
	// http server
	// advertise big picture
	http.HandleFunc("/bigpicture", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(k.k8sBigPicture)
	})
}

func (k *K8sCollector) Init(events chan interface{}) error {
	log.Logger.Info().Msg("k8sCollector initializing...")
	// stop signal for the informer
	k.k8sBigPicture = &K8sBigPicture{
		NamespaceToResources: make(map[string]K8sNamespaceResources),
	}
	k.Events = events

	go k.advertiseBigPicture()

	stopper := make(chan struct{})
	k.stopper = stopper
	defer close(stopper)

	// go k.informersFactory.Start(k.stopper)

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

	for _, watcher := range k.watchers {
		go watcher.Run(stopper)
	}

	<-stopper

	return nil
}

func NewK8sCollector() (*K8sCollector, error) {
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

	factory := informers.NewSharedInformerFactory(clientset, 0)

	return &K8sCollector{
		informersFactory: factory,
		watchers:         map[K8SResourceType]cache.SharedIndexInformer{},
	}, nil
}

type K8sNamespaceResources struct {
	Pods     map[string]corev1.Pod     `json:"pods"`     // map[podName]Pod
	Services map[string]corev1.Service `json:"services"` // map[serviceName]Service
}

type K8sBigPicture struct {
	NamespaceToResources map[string]K8sNamespaceResources `json:"namespaceToResources"` // map[namespace]K8sNamespaceResources
}

type K8sResourceMessage struct {
	ResourceType string      `json:"type"`
	EventType    string      `json:"eventType"`
	Object       interface{} `json:"object"`
}
