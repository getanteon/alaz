package datastore

type DataStore interface {
	CreatePod(pod Pod) error
	UpdatePod(pod Pod) error
	DeletePod(pod Pod) error
	CreateService(service Service) error
	UpdateService(service Service) error
	DeleteService(service Service) error
	PersistRequest(request Request) error
}
