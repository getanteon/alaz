package datastore

import "time"

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

type Request struct {
	StartTime  time.Time
	Latency    uint64 // in ns
	FromIP     string
	FromType   string
	FromUID    string
	ToIP       string
	ToType     string
	ToUID      string
	Protocol   string
	Completed  bool
	StatusCode uint32
	FailReason string
	Method     string
	Path       string
}
