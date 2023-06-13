package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"

	"alaz/log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	v1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

type K8SResourceType string

const (
	Service = "Service"
	Pod     = "Pod"
)

type K8sCollector struct {
	informersFactory informers.SharedInformerFactory
	watchers         map[K8SResourceType]cache.SharedIndexInformer
	stopper          chan struct{} // stop signal for the informer
	// watchers
	podInformer     v1.PodInformer
	serviceInformer v1.ServiceInformer

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

func (k *K8sCollector) Init() error {
	log.Logger.Info().Msg("k8sCollector initializing...")
	// stop signal for the informer
	k.k8sBigPicture = &K8sBigPicture{
		NamespaceToResources: make(map[string]K8sNamespaceResources),
	}
	k.Events = make(chan interface{}, 100) // TODO: make this configurable

	go k.advertiseBigPicture()

	stopper := make(chan struct{})
	k.stopper = stopper
	defer close(stopper)

	// go k.informersFactory.Start(k.stopper)

	// Pod
	k.podInformer = k.informersFactory.Core().V1().Pods()
	k.watchers[Pod] = k.podInformer.Informer()

	// Service
	k.serviceInformer = k.informersFactory.Core().V1().Services()
	k.watchers[Service] = k.informersFactory.Core().V1().Services().Informer()

	defer runtime.HandleCrash()

	// Add event handlers
	k.watchers[Pod].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddPodFunc(k.k8sBigPicture, k.Events),
		UpdateFunc: getOnUpdatePodFunc(k.k8sBigPicture),
		DeleteFunc: getOnDeleteFunc(k.k8sBigPicture),
	})

	k.watchers[Service].AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    getOnAddServiceFunc(k.k8sBigPicture, k.Events),
		UpdateFunc: getOnUpdateServiceFunc(k.k8sBigPicture),
		DeleteFunc: getOnDeleteServiceFunc(k.k8sBigPicture),
	})

	for _, watcher := range k.watchers {
		go watcher.Run(stopper)
	}

	<-stopper

	return nil
}

func NewK8sCollector() (*K8sCollector, error) {
	// get incluster kubeconfig
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("unable to get incluster kubeconfig: %w", err)
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
	Object       interface{} `json:"object"` // TODO: make this generic, add converter ?
}

// TODO: send update and delete events to the channel
func getOnAddPodFunc(k8sBigPicture *K8sBigPicture, ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		newPod := obj.(*corev1.Pod)
		ns := newPod.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		k8sBigPicture.NamespaceToResources[ns].Pods[newPod.Name] = *newPod

		ch <- K8sResourceMessage{
			ResourceType: Pod,
			EventType:    "add",
			Object:       newPod,
		}
	}
}

func getOnUpdatePodFunc(k8sBigPicture *K8sBigPicture) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		// TODO: find diff ?
		newPod := newObj.(*corev1.Pod)
		ns := newPod.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		k8sBigPicture.NamespaceToResources[ns].Pods[newPod.Name] = *newPod
	}
}

func getOnDeleteFunc(k8sBigPicture *K8sBigPicture) func(interface{}) {
	return func(obj interface{}) {
		deletedPod := obj.(*corev1.Pod)
		ns := deletedPod.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		delete(k8sBigPicture.NamespaceToResources[ns].Pods, deletedPod.Name)
	}
}

func getOnAddServiceFunc(k8sBigPicture *K8sBigPicture, ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		newService := obj.(*corev1.Service)
		ns := newService.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		k8sBigPicture.NamespaceToResources[ns].Services[newService.Name] = *newService

		ch <- K8sResourceMessage{
			ResourceType: Service,
			EventType:    "add",
			Object:       newService,
		}
	}
}

func getOnUpdateServiceFunc(k8sBigPicture *K8sBigPicture) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		// TODO: find diff ?
		newService := newObj.(*corev1.Service)
		ns := newService.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		k8sBigPicture.NamespaceToResources[ns].Services[newService.Name] = *newService
	}
}

func getOnDeleteServiceFunc(k8sBigPicture *K8sBigPicture) func(interface{}) {
	return func(obj interface{}) {
		deletedService := obj.(*corev1.Service)
		ns := deletedService.Namespace

		if _, ok := k8sBigPicture.NamespaceToResources[ns]; !ok {
			k8sBigPicture.NamespaceToResources[ns] = K8sNamespaceResources{
				Pods:     map[string]corev1.Pod{},
				Services: map[string]corev1.Service{},
			}
		}

		delete(k8sBigPicture.NamespaceToResources[ns].Services, deletedService.Name)
	}
}
