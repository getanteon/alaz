package k8s

func getOnAddDaemonSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DAEMONSET,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateDaemonSetFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DAEMONSET,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteDaemonSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DAEMONSET,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
