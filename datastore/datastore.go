package datastore

import (
	"github.com/ddosify/alaz/ebpf/l7_req"
	"github.com/ddosify/alaz/log"
)

type DataStore interface {
	PersistPod(pod Pod, eventType string) error
	PersistService(service Service, eventType string) error
	PersistReplicaSet(rs ReplicaSet, eventType string) error
	PersistDeployment(d Deployment, eventType string) error
	PersistEndpoints(e Endpoints, eventType string) error
	PersistContainer(c Container, eventType string) error
	PersistDaemonSet(ds DaemonSet, eventType string) error

	PersistRequest(request *Request) error

	PersistTraceEvent(trace *l7_req.TraceEvent) error
}

type MockDataStore struct {
}

func (m *MockDataStore) PersistPod(pod Pod, eventType string) error {
	log.Logger.Debug().Str("pod", pod.Name).Msg("PersistPod")
	return nil
}

func (m *MockDataStore) PersistService(service Service, eventType string) error {
	log.Logger.Debug().Str("service", service.Name).Msg("PersistService")
	return nil
}

func (m *MockDataStore) PersistReplicaSet(rs ReplicaSet, eventType string) error {
	log.Logger.Debug().Str("replicaset", rs.Name).Msg("PersistReplicaSet")
	return nil
}

func (m *MockDataStore) PersistDeployment(d Deployment, eventType string) error {
	log.Logger.Debug().Str("deployment", d.Name).Msg("PersistDeployment")
	return nil
}

func (m *MockDataStore) PersistEndpoints(e Endpoints, eventType string) error {
	log.Logger.Debug().Str("endpoints", e.Name).Msg("PersistEndpoints")
	return nil
}

func (m *MockDataStore) PersistContainer(c Container, eventType string) error {
	log.Logger.Debug().Str("container", c.Name).Msg("PersistContainer")
	return nil
}

func (m *MockDataStore) PersistDaemonSet(ds DaemonSet, eventType string) error {
	log.Logger.Debug().Str("daemonset", ds.Name).Msg("PersistDaemonSet")
	return nil
}

func (m *MockDataStore) PersistRequest(request *Request) error {
	log.Logger.Debug().Bool("isTls", request.Tls).Str("path", request.Path).Msg("PersistRequest")
	return nil
}

func (m *MockDataStore) PersistTraceEvent(trace *l7_req.TraceEvent) error {
	return nil
}
