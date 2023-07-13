package k8s

func getOnAddPodFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: POD,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdatePodFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: POD,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeletePodFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: POD,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
