package aggregator

import (
	"alaz/datastore"
	"alaz/k8s"
	"alaz/log"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	ADD    = "ADD"
	UPDATE = "UPDATE"
	DELETE = "DELETE"
)

func (a *Aggregator) persistPod(dto datastore.Pod, eventType string) {
	err := a.ds.PersistPod(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on PersistPod call to %s", eventType)
	}
}

func (a *Aggregator) processPod(d k8s.K8sResourceMessage) {
	pod := d.Object.(*corev1.Pod)

	var ownerType, ownerID, ownerName string
	if len(pod.OwnerReferences) > 0 {
		ownerType = pod.OwnerReferences[0].Kind
		ownerID = string(pod.OwnerReferences[0].UID)
		ownerName = pod.OwnerReferences[0].Name
	} else {
		log.Logger.Debug().Msgf("Pod %s/%s has no owner, event: %s", pod.Namespace, pod.Name, d.EventType)
	}

	dtoPod := datastore.Pod{
		UID:       string(pod.UID),
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Image:     pod.Spec.Containers[0].Image, // main containers
		IP:        pod.Status.PodIP,

		// Assuming that there is only one owner
		OwnerType: ownerType,
		OwnerID:   ownerID,
		OwnerName: ownerName,
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
	err := a.ds.PersistService(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on PersistService call to %s", eventType)
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

func (a *Aggregator) persistReplicaSet(dto datastore.ReplicaSet, eventType string) {
	err := a.ds.PersistReplicaSet(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on persistReplicaset call to %s", eventType)
	}
}

func (a *Aggregator) processReplicaSet(d k8s.K8sResourceMessage) {
	replicaSet := d.Object.(*appsv1.ReplicaSet)

	var ownerType, ownerID, ownerName string
	if len(replicaSet.OwnerReferences) > 0 {
		ownerType = replicaSet.OwnerReferences[0].Kind
		ownerID = string(replicaSet.OwnerReferences[0].UID)
		ownerName = replicaSet.OwnerReferences[0].Name
	} else {
		log.Logger.Debug().Msgf("ReplicaSet %s/%s has no owner, event: %s", replicaSet.Namespace, replicaSet.Name, d.EventType)
	}

	dtoReplicaSet := datastore.ReplicaSet{
		UID:       string(replicaSet.UID),
		Name:      ownerName,
		Namespace: replicaSet.Namespace,
		OwnerType: ownerType,
		OwnerID:   ownerID,
		OwnerName: ownerName,
		Replicas:  replicaSet.Status.Replicas,
	}

	switch d.EventType {
	case k8s.ADD:
		go a.persistReplicaSet(dtoReplicaSet, ADD)
	case k8s.UPDATE:
		go a.persistReplicaSet(dtoReplicaSet, UPDATE)
	case k8s.DELETE:
		go a.persistReplicaSet(dtoReplicaSet, DELETE)
	}

}

func (a *Aggregator) processDeployment(d k8s.K8sResourceMessage) {
	deployment := d.Object.(*appsv1.Deployment)

	dto := datastore.Deployment{
		UID:       string(deployment.UID),
		Name:      deployment.Name,
		Namespace: deployment.Namespace,
		Replicas:  deployment.Status.Replicas,
	}

	switch d.EventType {
	case k8s.ADD:
		go a.ds.PersistDeployment(dto, ADD)
	case k8s.UPDATE:
		go a.ds.PersistDeployment(dto, UPDATE)
	case k8s.DELETE:
		go a.ds.PersistDeployment(dto, DELETE)
	}

}
