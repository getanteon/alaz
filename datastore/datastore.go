package datastore

type DataStore interface {
	PersistPod(pod Pod, eventType string) error
	PersistService(service Service, eventType string) error
	PersistReplicaSet(rs ReplicaSet, eventType string) error
	PersistDeployment(d Deployment, eventType string) error

	PersistRequest(request Request) error
}
