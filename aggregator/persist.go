package aggregator

import (
	"alaz/datastore"
	"alaz/k8s"
	"alaz/log"

	corev1 "k8s.io/api/core/v1"
)

const (
	ADD    = "ADD"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

func (a *Aggregator) persistPod(dtoPod datastore.Pod, eventType string) {
	var callName string
	var err error
	switch eventType {
	case ADD:
		callName = "CreatePod"
		err = a.ds.CreatePod(dtoPod)
	case UPDATE:
		callName = "UpdatePod"
		err = a.ds.UpdatePod(dtoPod)
	case DELETE:
		callName = "DeletePod"
		err = a.ds.DeletePod(dtoPod)
	default:
		log.Logger.Error().Msg("unknown event type")
		return
	}

	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on %s call to %s", callName, a.dsDestination)
	}
}

func (a *Aggregator) processPod(d k8s.K8sResourceMessage) {
	pod := d.Object.(*corev1.Pod)
	dtoPod := datastore.Pod{
		UID:       string(pod.UID),
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Image:     pod.Spec.Containers[0].Image, // main containers
		IP:        pod.Status.PodIP,

		// Assuming that there is only one owner
		OwnerType: pod.OwnerReferences[0].Kind,
		OwnerID:   string(pod.OwnerReferences[0].UID),
		OwnerName: pod.OwnerReferences[0].Name,
	}

	switch d.EventType {
	case k8s.ADD:
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.PodIPToNamespace[pod.Status.PodIP] = pod.Namespace
		go a.persistPod(dtoPod, ADD)
	case k8s.UPDATE:
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.PodIPToNamespace[pod.Status.PodIP] = pod.Namespace
		go a.persistPod(dtoPod, UPDATE)
	case k8s.DELETE:
		delete(a.clusterInfo.PodIPToPodUid, pod.Status.PodIP)
		delete(a.clusterInfo.PodIPToNamespace, pod.Status.PodIP)
		go a.persistPod(dtoPod, DELETE)
	}
}

func (a *Aggregator) persistSvc(dto datastore.Service, eventType string) {
	var callName string
	var err error
	switch eventType {
	case ADD:
		callName = "CreateService"
		err = a.ds.CreateService(dto)
	case UPDATE:
		callName = "UpdateService"
		err = a.ds.UpdateService(dto)
	case DELETE:
		callName = "DeleteService"
		err = a.ds.DeleteService(dto)
	default:
		log.Logger.Error().Msg("unknown event type")
		return
	}

	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on %s call to %s", callName, a.dsDestination)
	}
}

func (a *Aggregator) processSvc(d k8s.K8sResourceMessage) {
	service := d.Object.(*corev1.Service)

	ports := []struct {
		Src      int32  "json:\"src\""
		Dest     int32  "json:\"dest\""
		Protocol string "json:\"protocol\""
	}{}

	for _, port := range service.Spec.Ports {
		ports = append(ports, struct {
			Src      int32  "json:\"src\""
			Dest     int32  "json:\"dest\""
			Protocol string "json:\"protocol\""
		}{
			Src:      port.Port,
			Dest:     port.NodePort,
			Protocol: string(port.Protocol),
		})
	}

	dtoSvc := datastore.Service{
		UID:        string(service.UID),
		Name:       service.Name,
		Namespace:  service.Namespace,
		Type:       string(service.Spec.Type),
		ClusterIPs: service.Spec.ClusterIPs,
		Ports:      ports,
	}

	switch d.EventType {
	case k8s.ADD:
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.ServiceIPToNamespace[service.Spec.ClusterIP] = service.Namespace
		go a.persistSvc(dtoSvc, ADD)
	case k8s.UPDATE:
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.ServiceIPToNamespace[service.Spec.ClusterIP] = service.Namespace
		go a.persistSvc(dtoSvc, UPDATE)
	case k8s.DELETE:
		delete(a.clusterInfo.ServiceIPToServiceUid, service.Spec.ClusterIP)
		delete(a.clusterInfo.ServiceIPToNamespace, service.Spec.ClusterIP)
		go a.persistSvc(dtoSvc, DELETE)
	}
}
