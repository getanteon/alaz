package cri

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ddosify/alaz/log"
	//nolint:staticcheck
	//nolint:staticcheck
	internalapi "k8s.io/cri-api/pkg/apis"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

// https://kubernetes.io/docs/setup/production-environment/container-runtimes/#cri-versions
var defaultRuntimeEndpoints = []string{"unix:///proc/1/root/run/containerd/containerd.sock", "unix:///proc/1/root/var/run/containerd/containerd.sock",
	"unix:///proc/1/root/var/run/crio/crio.sock", "unix:///proc/1/root/run/crio/crio.sock",
	"unix:///proc/1/root/run/cri-dockerd.sock", "unix:///proc/1/root/var/run/cri-dockerd.sock"}

type ContainerPodInfo struct {
	PodUid        string
	PodName       string
	PodNs         string
	ContainerName string
}

type CRITool struct {
	rs internalapi.RuntimeService
}

func NewCRITool(ctx context.Context) (*CRITool, error) {
	var res internalapi.RuntimeService
	var err error
	t := 10 * time.Second
	for _, endPoint := range defaultRuntimeEndpoints {
		res, err = remote.NewRemoteRuntimeService(endPoint, t, nil)
		if err != nil {
			continue
		}

		log.Logger.Info().Msgf("Connected successfully to CRI using endpoint %s", endPoint)
		break
	}

	if err != nil {
		return nil, err
	}

	return &CRITool{
		rs: res,
	}, nil
}

func (ct *CRITool) GetAllContainers() ([]*pb.Container, error) {
	// get running containers
	st := &pb.ContainerStateValue{}
	st.State = pb.ContainerState_CONTAINER_RUNNING

	filter := &pb.ContainerFilter{
		Id:                   "",
		State:                st,
		PodSandboxId:         "",
		LabelSelector:        map[string]string{},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_sizecache:        0,
	}

	list, err := ct.rs.ListContainers(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	return list, nil
}

// get log path of container
// id string : containerID
func (ct *CRITool) GetLogPath(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("containerID cannot be empty")
	}

	r, err := ct.rs.ContainerStatus(context.TODO(), id, true)
	if err != nil {
		return "", err
	}
	if r.Status.LogPath == "" {
		return "", fmt.Errorf("log path is empty for %s", id)
	}

	return fmt.Sprintf("/proc/1/root%s", r.Status.LogPath), nil
}

type ContainerInfo struct {
	ContainerID   string
	ContainerName string
	PodID         string
	PodName       string
	PodNamespace  string
}

func (ct *CRITool) GetContainerInfoWithPid(pid uint32) (*ContainerInfo, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)

	file, err := os.Open(cgroupFile)
	if err != nil {
		return nil, err
	}

	defer file.Close()

	// 0::/system.slice/kubepods-besteffort-pod8588024e_5678_4be0_aa19_f788c489e440.slice:cri-containerd:3fc51bb24ebb4ee5ea43ce0bc4a4296334d928872c0e4f90687ac7faeb8e379b
	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var containerID, podID string
	// trim newline
	line := string(bytes[:len(bytes)-1])

	// 0::/system.slice/kubepods-besteffort-pod511a4124_d284_4787_9678_ef15acfa5783.slice:cri-containerd:8cd2ad2d1d5f5b3a95de3e78fdabb667d17214e0dd2427ac033162159793db46\n
	log.Logger.Info().Str("line", line).Msg("GetContainerInfoWithPid")

	if !strings.HasPrefix(line, "0::/system.slice/") {
		return nil, fmt.Errorf("not a container cgroup")
	}

	line = strings.TrimPrefix(line, "0::/system.slice/")

	fields := strings.Split(line, ":")

	if len(fields) < 3 {
		return nil, fmt.Errorf("not a container cgroup")
	}

	// for _, field := range fields {
	// 	fmt.Println(field)
	// 	// kubepods-besteffort-pod3a57a863_71e7_4481_a010_a8a9f931c626.slice
	// 	// cri-containerd
	// 	// f7503333d9b5ef0b89d317cfcb8e5c7240fb01db7f557906d65fd9a3e9631b85
	// }

	// extract podID
	// kubepods-besteffort.slice
	// kubepods-burstable.slice

	podIndex := strings.LastIndex(fields[0], "pod")
	sliceIndex := strings.Index(fields[0], ".slice")

	if podIndex != -1 || sliceIndex != -1 {
		podID = fields[0][podIndex+3 : sliceIndex]
	} else {
		return nil, fmt.Errorf("podID not found in cgroup")
	}

	containerID = fields[len(fields)-1]

	info, err := ct.ContainerStatus(containerID)
	if err != nil {
		return nil, fmt.Errorf("could not get container info with id %s", containerID)
	}

	return &ContainerInfo{
		PodID:         podID,
		ContainerID:   containerID,
		PodName:       info.PodName,
		PodNamespace:  info.PodNs,
		ContainerName: info.ContainerName,
	}, nil
}

func (ct *CRITool) ContainerStatus(id string) (*ContainerPodInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("ID cannot be empty")
	}

	verbose := true

	r, err := ct.rs.ContainerStatus(context.TODO(), id, verbose)
	if err != nil {
		return nil, err
	}

	containerName := r.Status.Metadata.Name

	info := map[string]interface{}{}
	json.Unmarshal([]byte(r.Info["info"]), &info)

	sandBoxID := info["sandboxID"].(string)

	podRes, err := ct.rs.PodSandboxStatus(context.TODO(), sandBoxID, verbose)
	if err != nil {
		return nil, err
	}

	podUid := podRes.Status.Metadata.Uid
	podName := podRes.Status.Metadata.Name
	podNamespace := podRes.Status.Metadata.Namespace

	return &ContainerPodInfo{
		PodUid:        podUid,
		PodName:       podName,
		PodNs:         podNamespace,
		ContainerName: containerName,
	}, nil
}

func (ct *CRITool) getContainersOfPod(podSandboxId string) ([]*pb.Container, error) {
	// get running containers
	st := &pb.ContainerStateValue{}
	st.State = pb.ContainerState_CONTAINER_RUNNING

	filter := &pb.ContainerFilter{
		Id:                   "",
		State:                st,
		PodSandboxId:         podSandboxId,
		LabelSelector:        map[string]string{},
		XXX_NoUnkeyedLiteral: struct{}{},
		XXX_sizecache:        0,
	}

	list, err := ct.rs.ListContainers(context.TODO(), filter)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (ct *CRITool) getPod(podUid string) ([]*pb.PodSandbox, error) {
	filter := &pb.PodSandboxFilter{}

	filter.LabelSelector = map[string]string{
		// "app":                         "alaz",
		// "io.kubernetes.pod.name": "alaz-daemonset-rfdgt",
		// "io.kubernetes.pod.namespace": "ddosify",
		"io.kubernetes.pod.uid": podUid,
	}
	st := &pb.PodSandboxStateValue{
		State: pb.PodSandboxState_SANDBOX_READY,
	}
	filter.State = st

	return ct.rs.ListPodSandbox(context.Background(), filter)
}
