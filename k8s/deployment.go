package k8s

func getOnAddDeploymentSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DEPLOYMENT,
			EventType:    ADD,
			Object:       obj,
		}
	}
}

func getOnUpdateDeploymentSetFunc(ch chan interface{}) func(interface{}, interface{}) {
	return func(oldObj, newObj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DEPLOYMENT,
			EventType:    UPDATE,
			Object:       newObj,
		}
	}
}

func getOnDeleteDeploymentSetFunc(ch chan interface{}) func(interface{}) {
	return func(obj interface{}) {
		ch <- K8sResourceMessage{
			ResourceType: DEPLOYMENT,
			EventType:    DELETE,
			Object:       obj,
		}
	}
}
