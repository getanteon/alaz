package cri

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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
	PodUid        string
	PodName       string
	PodNs         string
	ContainerName string
}

type CRITool struct {
	rs         internalapi.RuntimeService
	nsFilterRx *regexp.Regexp
	ctx        context.Context
}

// parse podID and containerID from /proc/<pid>/cgroup file
var parseCgroupFunc func(string) (string, string, error)

func init() {
	parseCgroupFunc = parseCgroupV1
	cmd := exec.Command("stat", "-fc", "%T", "/sys/fs/cgroup/")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Logger.Warn().Msg("Unable to find cgroup version: %s, assuming v1")
		return
	}

	fsType := strings.TrimSuffix(string(output), "\n")
	switch fsType {
	case "tmpfs":
		parseCgroupFunc = parseCgroupV1
	case "cgroup2fs":
		parseCgroupFunc = parseCgroupV2
	default:
		log.Logger.Warn().Msgf("Unknown filesystem type for cgroups: %s, assuming v1", fsType)
		parseCgroupFunc = parseCgroupV1
	}
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

	var nsFilterRx *regexp.Regexp
	if os.Getenv("EXCLUDE_NAMESPACES") != "" {
		nsFilterRx = regexp.MustCompile(os.Getenv("EXCLUDE_NAMESPACES"))
	}

	return &CRITool{
		rs:         res,
		nsFilterRx: nsFilterRx,
		ctx:        ctx,
	}, nil
}

func (ct *CRITool) FilterNamespace(ns string) bool {
	if ns == "kube-system" {
		return true
	}
	if ct.nsFilterRx == nil {
		return false
	}
	if ct.nsFilterRx.MatchString(ns) {
		log.Logger.Debug().Msgf("%s filtered with EXCLUDE_NAMESPACES regex %s", ns, ct.nsFilterRx.String())
		return true
	}

	return false
}

func (ct *CRITool) FilterNamespaceWithContainerId(id string) bool {
	resp, err := ct.ContainerStatus(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get container status for container %s", id)
		return true
	}

	return ct.FilterNamespace(resp.PodNs)
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

	list, err := ct.rs.ListContainers(ct.ctx, filter)
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

	list, err := ct.rs.ListContainers(ct.ctx, filter)
	if err != nil {
		return nil, err
	}

	for _, c := range list {
		if ct.FilterNamespaceWithContainerId(c.Id) {
			log.Logger.Debug().Msgf("No tracking on ebpf side for container [%s] - [%s]", c.Id, c.Metadata.Name)
			continue
		}
		runningPids, err := ct.getAllRunningProcsInsideContainer(c.Id)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to get runnning pids for container [%s]", c.Id)
			continue
		}
		log.Logger.Debug().Msgf("running container [%s-%s] has pids %v", c.Metadata.Name, c.Id, runningPids)

		for _, pid := range runningPids {
			pids[pid] = struct{}{}
		}
	}
	return pids, nil
}

func (ct *CRITool) getAllRunningProcsInsideContainer(containerID string) ([]uint32, error) {
	r, err := ct.rs.ContainerStatus(ct.ctx, containerID, true)
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

	r, err := ct.rs.ContainerStatus(ct.ctx, id, true)
	if err != nil {
		return "", err
	}
	if r.Status.LogPath == "" {
		return "", fmt.Errorf("log path is empty for %s", id)
	}

	return fmt.Sprintf("/proc/1/root%s", r.Status.LogPath), nil
}

type ContainerInfo struct {
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name"`
	PodID         string `json:"pod_id"`
	PodName       string `json:"pod_name"`
	PodNamespace  string `json:"pod_namespace"`
}

func (ct *CRITool) GetContainerInfoWithPid(pid uint32) (*ContainerInfo, error) {
	podID, containerID, err := parseCgroupFunc(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return nil, fmt.Errorf("could not parse cgroup info for pid %d: %v", pid, err)
	}

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

	r, err := ct.rs.ContainerStatus(ct.ctx, id, verbose)
	if err != nil {
		return nil, err
	}

	containerName := r.Status.Metadata.Name

	info := map[string]interface{}{}
	json.Unmarshal([]byte(r.Info["info"]), &info)

	sandBoxID := info["sandboxID"].(string)

	podRes, err := ct.rs.PodSandboxStatus(ct.ctx, sandBoxID, verbose)
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

	list, err := ct.rs.ListContainers(ct.ctx, filter)
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

	return ct.rs.ListPodSandbox(ct.ctx, filter)
}

func parseCgroupV1(filePath string) (string, string, error) {
	log.Logger.Debug().Msgf("Parsing cgroup v1 file: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// 1:name=systemd:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod57009a28_e677_4550_8e14_7724a18cc70c.slice/cri-containerd-62b0b04c0d518199a25d7cd859c376caf71a850374ce1d76fc7410e54dd63a10.scope
		line := scanner.Text()

		// split the lines based on the first occurrence of ':'; this will leave us with cgroup version and rest of the info separately
		parts := strings.SplitN(line, ":", 3)

		if len(parts) == 3 {
			values := strings.Split(parts[2], "/")
			if len(values) < 5 {
				return "", "", fmt.Errorf("unexpected cgroup format")
			}

			// Value 3: kubepods-burstable-pod57009a28_e677_4550_8e14_7724a18cc70c.slice
			// Value 4: cri-containerd-62b0b04c0d518199a25d7cd859c376caf71a850374ce1d76fc7410e54dd63a10.scope

			podInfo := values[len(values)-2]
			containerInfo := values[len(values)-1]

			podIndex := strings.LastIndex(podInfo, "pod")
			sliceIndex := strings.Index(podInfo, ".slice")
			podID := podInfo[podIndex+3 : sliceIndex]

			containerDashIndex := strings.LastIndex(containerInfo, "-")
			scopeIndex := strings.Index(containerInfo, ".scope")
			containerID := containerInfo[containerDashIndex+1 : scopeIndex]

			return podID, containerID, nil
		}
	}

	if scanner.Err() != nil {
		return "", "", scanner.Err()
	}

	return "", "", fmt.Errorf("unable to find cgroup info")
}

func parseCgroupV2(filePath string) (string, string, error) {
	log.Logger.Debug().Msgf("Parsing cgroup v2 file: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// 0::/system.slice/kubepods-burstable-pod22fd933a_ee61_46bd_93ae_ebace73c1160.slice:cri-containerd:3a31a360e5aea903274416e0c4cf8ca8c050fd523cc5d91a82ec5707d5ee9fa1
		line := scanner.Text()

		// split the lines based on the first occurrence of ':'; this will leave us with cgroup version and rest of the info separately
		parts := strings.SplitN(line, ":", 4)

		// cgroup v2 will have 0 in the first part
		if parts[0] != "0" {
			continue
		}

		// /system.slice/kubepods-burstable-pod22fd933a_ee61_46bd_93ae_ebace73c1160.slice
		podInfo := parts[len(parts)-2]
		values := strings.Split(podInfo, "/")

		// kubepods-burstable-pod22fd933a_ee61_46bd_93ae_ebace73c1160
		podInfoLastPart := values[len(values)-1]
		podIndex := strings.LastIndex(podInfoLastPart, "pod")
		sliceIndex := strings.Index(podInfoLastPart, ".slice")

		podID := podInfoLastPart[podIndex+3 : sliceIndex]

		// cri-containerd:3a31a360e5aea903274416e0c4cf8ca8c050fd523cc5d91a82ec5707d5ee9fa1
		containerInfo := parts[len(parts)-1]
		values = strings.Split(containerInfo, ":")
		containerID := values[len(values)-1]

		return podID, containerID, nil
	}

	if scanner.Err() != nil {
		return "", "", scanner.Err()
	}

	return "", "", fmt.Errorf("unable to find cgroup info")
}
