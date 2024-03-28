package cri

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ddosify/alaz/log"
	"github.com/prometheus/procfs"

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
	PodUid  string
	PodName string
	PodNs   string
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

func (ct *CRITool) GetPidsRunningOnContainers() (map[uint32]struct{}, error) {
	pids := make(map[uint32]struct{})
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

	for _, c := range list {
		runningPids, err := ct.getAllRunningProcsInsideContainer(c.Id)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to get runnning pids for container %s", c.Id)
			continue
		}
		log.Logger.Debug().Msgf("running container %s-%s has pids %v", c.Metadata.Name, c.Id, runningPids)

		for _, pid := range runningPids {
			pids[pid] = struct{}{}
		}
	}
	return pids, nil
}

func (ct *CRITool) getAllRunningProcsInsideContainer(containerID string) ([]uint32, error) {
	r, err := ct.rs.ContainerStatus(context.TODO(), containerID, true)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get container status for container %s", containerID)
		return nil, err
	}

	info := map[string]interface{}{}
	json.Unmarshal([]byte(r.Info["info"]), &info)

	// pid of main process
	pidFloat := info["pid"].(float64)
	pid := int(pidFloat)

	fs, err := procfs.NewFS("/proc/1/root/proc")
	if err != nil {
		return nil, err
	}

	proc, err := fs.Proc(pid)
	if err != nil {
		return nil, err
	}

	// get cgroup hiearchies and read cgrou.procs file for pids
	cgroups, err := proc.Cgroups()
	if err != nil {
		return nil, err
	}

	result := []uint32{}

	for _, cgroup := range cgroups {
		if cgroup.HierarchyID == 0 { // cgroup v2
			procsPath := "/proc/1/root/sys/fs/cgroup" + cgroup.Path + "/cgroup.procs"
			// read proc pids
			pidFile, err := os.OpenFile(procsPath, os.O_RDONLY, 0)
			if err != nil {
				log.Logger.Warn().Err(err).Msgf("Error reading cgroup.procs file for cgroup %s", cgroup.Path)
				continue
			}
			defer pidFile.Close()
			fileScanner := bufio.NewScanner(pidFile)
			for fileScanner.Scan() {
				pid, err := strconv.ParseUint(fileScanner.Text(), 10, 32)
				if err != nil {
					log.Logger.Warn().Err(err).Msgf("Error parsing pid %s", fileScanner.Text())
					continue
				}
				result = append(result, uint32(pid))
			}
		} else { // v1 cgroup
			// use memory controller as default
			procsPath := "/proc/1/root/sys/fs/cgroup/memory" + cgroup.Path + "/cgroup.procs"
			// read proc pids
			pidFile, err := os.OpenFile(procsPath, os.O_RDONLY, 0)
			if err != nil {
				log.Logger.Warn().Err(err).Msgf("Error reading cgroup.procs file for cgroup %s", cgroup.Path)
				continue
			}
			defer pidFile.Close()
			fileScanner := bufio.NewScanner(pidFile)
			for fileScanner.Scan() {
				pid, err := strconv.ParseUint(fileScanner.Text(), 10, 32)
				if err != nil {
					log.Logger.Warn().Err(err).Msgf("Error parsing pid %s", fileScanner.Text())
					continue
				}
				result = append(result, uint32(pid))
			}
		}
	}
	return result, nil
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

func (ct *CRITool) ContainerStatus(id string) (*ContainerPodInfo, error) {
	if id == "" {
		return nil, fmt.Errorf("ID cannot be empty")
	}

	verbose := true

	r, err := ct.rs.ContainerStatus(context.TODO(), id, verbose)
	if err != nil {
		return nil, err
	}

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
		PodUid:  podUid,
		PodName: podName,
		PodNs:   podNamespace,
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
