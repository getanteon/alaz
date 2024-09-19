package k8s

func getOnAddK8SEventFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: K8SEVENT,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateK8SEventFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: K8SEVENT,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteK8SEventFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: K8SEVENT,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
