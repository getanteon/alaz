package main

import (
	"encoding/json"
	"fmt"
	"log"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

func main() {

	// get incluster kubeconfig
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal("Unable to get incluster kubeconfig", err)
	}

	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		log.Panic(err.Error())
	}

	// stop signal for the informer
	stopper := make(chan struct{})
	defer close(stopper)

	factory := informers.NewSharedInformerFactory(clientset, 0)
	podInformer := factory.Core().V1().Pods()
	podCacheSharedIndexInformer := podInformer.Informer()

	serviceInformer := factory.Core().V1().Services()
	serviceCacheSharedIndexInformer := serviceInformer.Informer()

	defer runtime.HandleCrash()

	// start informer ->
	go factory.Start(stopper)

	// start to sync and call list
	if !cache.WaitForCacheSync(stopper, podCacheSharedIndexInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}
	if !cache.WaitForCacheSync(stopper, serviceCacheSharedIndexInformer.HasSynced) {
		runtime.HandleError(fmt.Errorf("Timed out waiting for caches to sync"))
		return
	}

	// Add event handlers
	podCacheSharedIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    onAddPod, // register add eventhandler
		UpdateFunc: func(interface{}, interface{}) { fmt.Println("update not implemented") },
		DeleteFunc: func(interface{}) { fmt.Println("delete not implemented") },
	})

	serviceCacheSharedIndexInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { fmt.Println("add not implemented") },
		UpdateFunc: func(interface{}, interface{}) { fmt.Println("update not implemented") },
		DeleteFunc: func(interface{}) { fmt.Println("delete not implemented") },
	})

	// find pods in one ns, or find pods from --all-namespaces
	podLister := podInformer.Lister().Pods("ddosify")
	_, err = podLister.List(labels.Everything())

	if err != nil {
		fmt.Println(err)
	}

	// fmt.Println("pods:", pods)

	serviceLister := serviceInformer.Lister().Services("ddosify")
	services, err := serviceLister.List(labels.Everything())

	if err != nil {
		fmt.Println(err)
	}

	jsonServ, _ := json.Marshal(services)
	fmt.Println("services:", string(jsonServ))

	<-stopper
}

// TODO: onAdd cagiriyolar

func onAddPod(obj interface{}) {
	newPod := obj.(*corev1.Pod)
	fmt.Println("newPod:", newPod.Name)
}

func onAddService(obj interface{}) {
	newService := obj.(*corev1.Service)
	fmt.Println("newService:", newService.Name)
}
