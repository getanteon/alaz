package k8s

func getOnAddServiceFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: SERVICE,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateServiceFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: SERVICE,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteServiceFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: SERVICE,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
