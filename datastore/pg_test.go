package datastore

import (
	"alaz/config"
	"testing"
)

func TestCreatePod(t *testing.T) {
	repo := NewRepository(config.PostgresConfig{
		Host:     "localhost",
		Port:     "5432",
		Username: "alazuser",
		Password: "alazpwd",
		DBName:   "alazdb",
	})

	pod := Pod{
		UID:       "uid24",
		Name:      "name",
		Namespace: "namespace",
		Image:     "image",
		IP:        "ip",
	}

	err := repo.CreatePod(pod)

	if err != nil {
		t.Errorf("Error creating pod: %v", err)
	}

}

func TestCreateUpdateService(t *testing.T) {
	repo := NewRepository(config.PostgresConfig{
		Host:     "localhost",
		Port:     "5432",
		Username: "alazuser",
		Password: "alazpwd",
		DBName:   "alazdb",
	})

	svc := Service{
		UID:       "uid55",
		Name:      "name",
		Namespace: "namespace",
		Type:      "type",
		ClusterIP: "clusterIP",
	}

	err := repo.CreateService(svc)

	if err != nil {
		t.Errorf("Error creating service: %v", err)
	}

	// update service
	svc.Type = "type2"
	err = repo.UpdateService(svc)
	if err != nil {
		t.Errorf("Error updating service: %v", err)
	}
}
