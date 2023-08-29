package datastore

type DataStore interface {
	PersistPod(pod Pod, eventType string) error
	PersistService(service Service, eventType string) error
	PersistReplicaSet(rs ReplicaSet, eventType string) error
	PersistDeployment(d Deployment, eventType string) error
	PersistEndpoints(e Endpoints, eventType string) error
	PersistContainer(c Container, eventType string) error
	PersistDaemonSet(ds DaemonSet, eventType string) error

	PersistRequest(request Request) error
}
