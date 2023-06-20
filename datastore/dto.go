package datastore

type Pod struct {
	UID       string
	Name      string
	Namespace string
	Image     string
	IP        string
}

type Service struct {
	UID       string
	Name      string
	Namespace string
	Type      string
	ClusterIP string
}
