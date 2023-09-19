package k8s

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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

type K8sCollector struct {
	ctx              context.Context
	informersFactory informers.SharedInformerFactory
	watchers         map[K8SResourceType]cache.SharedIndexInformer
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

	factory := informers.NewSharedInformerFactory(clientset, 0)

	collector := &K8sCollector{
		ctx:              ctx,
		stopper:          make(chan struct{}),
		doneChan:         make(chan struct{}),
		informersFactory: factory,
		watchers:         map[K8SResourceType]cache.SharedIndexInformer{},
	}

	go func(c *K8sCollector) {
		<-c.ctx.Done() // wait for context to be cancelled
		c.close()
	}(collector)

	return collector, nil
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
