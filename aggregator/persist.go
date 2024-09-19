package aggregator

import (
	"github.com/ddosify/alaz/datastore"
	"github.com/ddosify/alaz/k8s"
	"github.com/ddosify/alaz/log"

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
		log.Logger.Error().Err(err).Msgf("error on PersistPod call to %s, uid: %s", eventType, dto.UID)
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

	if pod.Status.PodIP == "" {
		log.Logger.Debug().Msgf("Pod %s/%s has no IP, event: %s", pod.Namespace, pod.Name, d.EventType)
		return
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
		a.clusterInfo.k8smu.Lock()
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.k8smu.Unlock()
		go a.persistPod(dtoPod, ADD)
	case k8s.UPDATE:
		a.clusterInfo.k8smu.Lock()
		a.clusterInfo.PodIPToPodUid[pod.Status.PodIP] = pod.UID
		a.clusterInfo.k8smu.Unlock()
		go a.persistPod(dtoPod, UPDATE)
	case k8s.DELETE:
		a.clusterInfo.k8smu.Lock()
		delete(a.clusterInfo.PodIPToPodUid, pod.Status.PodIP)
		a.clusterInfo.k8smu.Unlock()
		go a.persistPod(dtoPod, DELETE)
	}
}

func (a *Aggregator) persistSvc(dto datastore.Service, eventType string) {
	err := a.ds.PersistService(dto, eventType)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("error on PersistService call to %s, uid: %s", eventType, dto.UID)
	}
}

func (a *Aggregator) processSvc(d k8s.K8sResourceMessage) {
	service := d.Object.(*corev1.Service)

	ports := []struct {
		Name     string "json:\"name\""
		Src      int32  "json:\"src\""
		Dest     int32  "json:\"dest\""
		Protocol string "json:\"protocol\""
	}{}

	for _, port := range service.Spec.Ports {
		ports = append(ports, struct {
			Name     string "json:\"name\""
			Src      int32  "json:\"src\""
			Dest     int32  "json:\"dest\""
			Protocol string "json:\"protocol\""
		}{
			Name:     port.Name, // https://kubernetes.io/docs/concepts/services-networking/service/#field-spec-ports
			Src:      port.Port,
			Dest:     int32(port.TargetPort.IntValue()),
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
		a.clusterInfo.k8smu.Lock()
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.k8smu.Unlock()
		go a.persistSvc(dtoSvc, ADD)
	case k8s.UPDATE:
		a.clusterInfo.k8smu.Lock()
		a.clusterInfo.ServiceIPToServiceUid[service.Spec.ClusterIP] = service.UID
		a.clusterInfo.k8smu.Unlock()
		go a.persistSvc(dtoSvc, UPDATE)
	case k8s.DELETE:
		a.clusterInfo.k8smu.Lock()
		delete(a.clusterInfo.ServiceIPToServiceUid, service.Spec.ClusterIP)
		a.clusterInfo.k8smu.Unlock()
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
		go func() {
			err := a.ds.PersistDeployment(dto, ADD)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistDeployment call to %s, uid: %s", ADD, dto.UID)
			}
		}()
	case k8s.UPDATE:
		go func() {
			err := a.ds.PersistDeployment(dto, UPDATE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistDeployment call to %s, uid: %s", UPDATE, dto.UID)
			}
		}()
	case k8s.DELETE:
		go func() {
			err := a.ds.PersistDeployment(dto, DELETE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistDeployment call to %s, uid: %s", DELETE, dto.UID)
			}
		}()
	}
}

func (a *Aggregator) processContainer(d k8s.K8sResourceMessage) {
	c := d.Object.(*k8s.Container)

	dto := datastore.Container{
		Name:      c.Name,
		Namespace: c.Namespace,
		PodUID:    c.PodUID,
		Image:     c.Image,
		Ports:     c.Ports,
	}

	switch d.EventType {
	case k8s.ADD:
		go func() {
			err := a.ds.PersistContainer(dto, ADD)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistContainer call to %s", ADD)
			}
		}()
	case k8s.UPDATE:
		go func() {
			err := a.ds.PersistContainer(dto, UPDATE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistContainer call to %s", UPDATE)
			}
		}()
		// No need for  delete container
	}
}

func (a *Aggregator) processEndpoints(ep k8s.K8sResourceMessage) {
	endpoints := ep.Object.(*corev1.Endpoints)

	// subsets
	adrs := []datastore.Address{}

	// subset[0].address -> ips
	// subset[0].ports -> ports

	for _, subset := range endpoints.Subsets {
		ips := []datastore.AddressIP{}
		ports := []datastore.AddressPort{}

		for _, addr := range subset.Addresses {
			// Probably external IP
			if addr.TargetRef == nil {
				ips = append(ips, datastore.AddressIP{
					IP: addr.IP,
				})
				continue
			}

			// TargetRef: Pod probably
			ips = append(ips, datastore.AddressIP{
				Type:      string(addr.TargetRef.Kind),
				ID:        string(addr.TargetRef.UID),
				Name:      addr.TargetRef.Name,
				Namespace: addr.TargetRef.Namespace,
				IP:        addr.IP,
			})
		}

		for _, port := range subset.Ports {
			ports = append(ports, datastore.AddressPort{
				Port:     port.Port,
				Protocol: string(port.Protocol),
				Name:     port.Name,
			})
		}

		adrs = append(adrs, datastore.Address{
			IPs:   ips,
			Ports: ports,
		})
	}

	dto := datastore.Endpoints{
		UID:       string(endpoints.UID),
		Name:      endpoints.Name,
		Namespace: endpoints.Namespace,
		Addresses: adrs,
	}

	switch ep.EventType {
	case k8s.ADD:
		go func() {
			err := a.ds.PersistEndpoints(dto, ADD)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistEndpoints call to %s, uid: %s", ADD, dto.UID)
			}
		}()
	case k8s.UPDATE:
		go func() {
			err := a.ds.PersistEndpoints(dto, UPDATE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistEndpoints call to %s, uid: %s", UPDATE, dto.UID)
			}
		}()
	case k8s.DELETE:
		go func() {
			err := a.ds.PersistEndpoints(dto, DELETE)
			if err != nil {
				log.Logger.Error().Err(err).Msgf("error on PersistEndpoints call to %s, uid: %s", DELETE, dto.UID)
			}
		}()
	}
}

func (a *Aggregator) processDaemonSet(d k8s.K8sResourceMessage) {
	daemonSet := d.Object.(*appsv1.DaemonSet)

	dtoDaemonSet := datastore.DaemonSet{
		UID:       string(daemonSet.UID),
		Name:      daemonSet.Name,
		Namespace: daemonSet.Namespace,
	}

	switch d.EventType {
	case k8s.ADD:
		go a.ds.PersistDaemonSet(dtoDaemonSet, ADD)
	case k8s.UPDATE:
		go a.ds.PersistDaemonSet(dtoDaemonSet, UPDATE)
	case k8s.DELETE:
		go a.ds.PersistDaemonSet(dtoDaemonSet, DELETE)
	}
}

func (a *Aggregator) processStatefulSet(d k8s.K8sResourceMessage) {
	statefulSet := d.Object.(*appsv1.StatefulSet)

	dtoStatefulSet := datastore.StatefulSet{
		UID:       string(statefulSet.UID),
		Name:      statefulSet.Name,
		Namespace: statefulSet.Namespace,
	}

	switch d.EventType {
	case k8s.ADD:
		go a.ds.PersistStatefulSet(dtoStatefulSet, ADD)
	case k8s.UPDATE:
		go a.ds.PersistStatefulSet(dtoStatefulSet, UPDATE)
	case k8s.DELETE:
		go a.ds.PersistStatefulSet(dtoStatefulSet, DELETE)
	}
}

func (a *Aggregator) processK8SEvent(d k8s.K8sResourceMessage) {
	event := d.Object.(*corev1.Event)

	dtoK8SEvent := datastore.K8SEvent{
		EventName:      event.Name,
		Kind:           event.InvolvedObject.Kind,
		Namespace:      event.InvolvedObject.Namespace,
		Name:           event.InvolvedObject.Name,
		Uid:            string(event.InvolvedObject.UID),
		Reason:         event.Reason,
		Message:        event.Message,
		Count:          event.Count,
		FirstTimestamp: event.FirstTimestamp.UnixMilli(),
		LastTimestamp:  event.LastTimestamp.UnixMilli(),
	}
	go a.ds.PersistK8SEvent(dtoK8SEvent)
}
