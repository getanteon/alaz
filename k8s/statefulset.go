package k8s

func getOnAddStatefulSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: STATEFULSET,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateStatefulSetFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: STATEFULSET,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteStatefulSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: STATEFULSET,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
