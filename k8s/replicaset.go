package k8s

func getOnAddReplicaSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: REPLICASET,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateReplicaSetFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: REPLICASET,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteReplicaSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: REPLICASET,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
