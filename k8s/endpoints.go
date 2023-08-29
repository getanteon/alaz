package k8s

func getOnAddEndpointsSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: ENDPOINTS,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateEndpointsSetFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: ENDPOINTS,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteEndpointsSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: ENDPOINTS,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
