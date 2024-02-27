package cri

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ddosify/alaz/log"

	// "github.com/gogo/protobuf/jsonpb"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/protobuf/jsonpb" //nolint:staticcheck
	"github.com/golang/protobuf/proto"  //nolint:staticcheck
	internalapi "k8s.io/cri-api/pkg/apis"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

var defaultRuntimeEndpoints = []string{"unix:///proc/1/root/run/containerd/containerd.sock", "unix:///proc/1/root/run/crio/crio.sock", "unix:///proc/1/root/var/run/cri-dockerd.sock"}

type CRITool struct {
	rs      internalapi.RuntimeService
	timeout time.Duration

	connPool *sync.Pool
	watcher  *fsnotify.Watcher

	logPathToFile          map[string]*bufio.Reader
	logPathToContainerMeta map[string]string
}

func NewCRITool(ctx context.Context, t time.Duration) (*CRITool, error) {
	var res internalapi.RuntimeService
	var err error
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

	logBackend := os.Getenv("LOG_BACKEND")
	if logBackend == "" {
		logBackend = "log-backend.ddosify:8282"
	}

	connPool := &sync.Pool{
		New: func() interface{} {
			conn, err := net.Dial("tcp", logBackend)
			if err != nil {
				log.Logger.Error().Err(err).Msg("Failed to dial log backend")
				return nil
			}
			log.Logger.Debug().Msg("Connected to log backend")
			return conn
		},
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create fsnotify watcher")
	}

	go func() {
		<-ctx.Done()
		watcher.Close()
	}()

	logPathToFile := make(map[string]*bufio.Reader, 0)
	logPathToContainerMeta := make(map[string]string, 0)

	return &CRITool{
		rs:                     res,
		connPool:               connPool,
		watcher:                watcher,
		logPathToFile:          logPathToFile,
		logPathToContainerMeta: logPathToContainerMeta,
	}, nil
}

func (ct *CRITool) getAllContainers() ([]*pb.Container, error) {
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
func (ct *CRITool) getLogPath(id string) (string, error) {
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

type ContainerStatusResponse struct {
	podUid  string
	podName string
	podNs   string
}

func (ct *CRITool) containerStatus(id string) (*ContainerStatusResponse, error) {
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

	// logPath := r.Status.GetLogPath()
	// pid := info["pid"].(float64)

	sandBoxID := info["sandboxID"].(string)

	podRes, err := ct.rs.PodSandboxStatus(context.TODO(), sandBoxID, verbose)
	if err != nil {
		return nil, err
	}

	podUid := podRes.Status.Metadata.Uid
	podName := podRes.Status.Metadata.Name
	podNamespace := podRes.Status.Metadata.Namespace
	// fmt.Printf("containerID:%s\n", id)
	// fmt.Printf("podUid:%s podName:%s podNs:%s\n", podUid, podName, podNamespace)

	return &ContainerStatusResponse{
		podUid:  podUid,
		podName: podName,
		podNs:   podNamespace,
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

func (ct *CRITool) getPods(podUid string) ([]*pb.PodSandbox, error) {
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

// podUid
// containerName
// which version of container, 0,1,2...
func getContainerMetadataLine(podNs, podName, podUid, containerName string, num int) string {
	return fmt.Sprintf("**AlazLogs_%s_%s_%s_%s_%d**\n", podNs, podName, podUid, containerName, num)
}

func (ct *CRITool) readerForLogPath(logPath string) (*bufio.Reader, error) {
	// TODO: refactor
	if reader, ok := ct.logPathToFile[logPath]; ok {
		return reader, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(file)
	ct.logPathToFile[logPath] = reader

	return reader, nil
}

func (ct *CRITool) StreamLogs() error {
	containers, err := ct.getAllContainers()
	if err != nil {
		return err
	}

	for _, c := range containers {
		logPath, err := ct.getLogPath(c.Id)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to get log path for container %s, %s", c.Id, c.Metadata.Name)
			continue
		}
		_, err = ct.readerForLogPath(logPath)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to get reader for log path %s", logPath)
			continue
		}

		err = ct.watcher.Add(logPath)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
			continue
		}

		fileName := filepath.Base(logPath)
		fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
		suffixNum, err := strconv.Atoi(fileNameWithoutExt)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to parse numeric part of log file name %s", fileName)
		}

		// /var/log/pods/ddosify_log-pod-a_e77e90d7-c071-4e08-a467-76771bc399a0/log-container/0.log
		// TODO: parse logPath, direct metadataline

		resp, err := ct.containerStatus(c.Id)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to get container status for container %s", c.Id)
			continue
		}

		ct.logPathToContainerMeta[logPath] = getContainerMetadataLine(resp.podNs, resp.podName, resp.podUid, c.Metadata.Name, suffixNum)
	}

	// start listening for fsnotify events
	go func() {
		for {
			select {
			case event, ok := <-ct.watcher.Events:
				if !ok {
					return
				}

				if event.Has(fsnotify.Rename) { // logrotate case
					logPath := event.Name
					ct.watcher.Add(logPath)

					// TODO: on an error, and restart event log suffix is incremented
					// we need to know a way to handle this case
					// we need know about stopped containers, and new containers

					// at first try it can still not existent
					// so we need to wait for it to be created
					for {
						_, err := os.Stat(logPath)
						if err == nil {
							break
						} else {
							log.Logger.Info().Msgf("waiting for file to be created on rename: %s", logPath)
						}
						time.Sleep(1 * time.Second)
					}

					logFile, err := os.Open(logPath) // reopen file
					if err != nil {
						log.Logger.Error().Err(err).Msgf("Failed to reopen file on rename event: %s", logPath)
						continue
					}

					logFile.Seek(0, io.SeekEnd) // seek to end of file
					ct.logPathToFile[logPath] = bufio.NewReader(logFile)

					log.Logger.Info().Msgf("reopened file for rename: %s", logPath)
					continue
				} else if event.Has(fsnotify.Write) {
					var err error
					logPath := event.Name
					conn := ct.connPool.Get()

					// send metadata first
					metaLine := ct.logPathToContainerMeta[logPath]
					_, err = io.Copy(conn.(net.Conn), bytes.NewBufferString(metaLine))
					if err != nil {
						log.Logger.Error().Err(err).Msgf("metadata could not be sent to backend: %v", err)
						log.Logger.Error().Msgf("TODO: handle this error, backend may be down, connection may be closed for any reason, etc.")
						continue
					}

					// send logs
					reader, ok := ct.logPathToFile[logPath]
					if !ok || reader == nil {
						log.Logger.Error().Msgf("reader for log path %s is not found", logPath)
						continue
					}

					n, err := io.Copy(conn.(net.Conn), reader)
					if err != nil {
						log.Logger.Error().Err(err).Msgf("logs could not be sent to backend: %v", err)
						log.Logger.Error().Msgf("TODO: handle this error, backend may be down, connection may be closed for any reason, etc.")
						// TODO: try to reconnect
					}
					log.Logger.Debug().Msgf("written %d bytes to conn for %s", logPath)
					ct.connPool.Put(conn)
				}
			case err, ok := <-ct.watcher.Errors:
				if !ok {
					return
				}
				log.Logger.Error().Err(err).Msgf("fsnotify error")
			}
		}
	}()

	return nil
}

type listOptions struct {
	// id of container or sandbox
	id string
	// podID of container
	podID string
	// Regular expression pattern to match pod or container
	nameRegexp string
	// Regular expression pattern to match the pod namespace
	podNamespaceRegexp string
	// state of the sandbox
	state string
	// show verbose info for the sandbox
	verbose bool
	// labels are selectors for the sandbox
	labels map[string]string
	// quiet is for listing just container/sandbox/image IDs
	quiet bool
	// output format
	output string
	// all containers
	all bool
	// latest container
	latest bool
	// last n containers
	last int
	// out with truncating the id
	noTrunc bool
	// image used by the container
	image string
	// resolve image path
	resolveImagePath bool
}

func ListPodSandboxesV2(client internalapi.RuntimeService, opts listOptions) error {
	filter := &pb.PodSandboxFilter{}
	if opts.id != "" {
		filter.Id = opts.id
	}
	if opts.state != "" {
		st := &pb.PodSandboxStateValue{}
		st.State = pb.PodSandboxState_SANDBOX_NOTREADY
		switch strings.ToLower(opts.state) {
		case "ready":
			st.State = pb.PodSandboxState_SANDBOX_READY
			filter.State = st
		case "notready":
			st.State = pb.PodSandboxState_SANDBOX_NOTREADY
			filter.State = st
		default:
			log.Fatalf("--state should be ready or notready")
		}
	}
	if opts.labels != nil {
		filter.LabelSelector = opts.labels
	}
	// request := &pb.ListPodSandboxRequest{
	// 	Filter: filter,
	// }
	// logrus.Debugf("ListPodSandboxRequest: %v", request)
	r, err := client.ListPodSandbox(context.TODO(), filter)
	// logrus.Debugf("ListPodSandboxResponse: %v", r)
	if err != nil {
		return err
	}
	r = getSandboxesList(r, opts)

	switch opts.output {
	case "json":
		return outputProtobufObjAsJSON(&pb.ListPodSandboxResponse{Items: r})
	case "table":
	// continue; output will be generated after the switch block ends.
	default:
		return fmt.Errorf("unsupported output format %q", opts.output)
	}

	return nil
}

type sandboxByCreated []*pb.PodSandbox

func (a sandboxByCreated) Len() int      { return len(a) }
func (a sandboxByCreated) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a sandboxByCreated) Less(i, j int) bool {
	return a[i].CreatedAt > a[j].CreatedAt
}

type containerByCreated []*pb.Container

func (a containerByCreated) Len() int      { return len(a) }
func (a containerByCreated) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a containerByCreated) Less(i, j int) bool {
	return a[i].CreatedAt > a[j].CreatedAt
}

func getSandboxesList(sandboxesList []*pb.PodSandbox, opts listOptions) []*pb.PodSandbox {
	filtered := []*pb.PodSandbox{}
	for _, p := range sandboxesList {
		// Filter by pod name/namespace regular expressions.
		if matchesRegex(opts.nameRegexp, p.Metadata.Name) &&
			matchesRegex(opts.podNamespaceRegexp, p.Metadata.Namespace) {
			filtered = append(filtered, p)
		}
	}

	sort.Sort(sandboxByCreated(filtered))
	n := len(filtered)
	if opts.latest {
		n = 1
	}
	if opts.last > 0 {
		n = opts.last
	}
	n = func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}(n, len(filtered))

	return filtered[:n]
}

func outputProtobufObjAsJSON(obj proto.Message) error {
	marshaledJSON, err := protobufObjectToJSON(obj)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("here")
	fmt.Println(marshaledJSON)
	return nil
}

func protobufObjectToJSON(obj proto.Message) (string, error) {
	jsonpbMarshaler := jsonpb.Marshaler{EmitDefaults: true, Indent: "  "}
	marshaledJSON, err := jsonpbMarshaler.MarshalToString(obj)
	if err != nil {
		return "", err
	}
	return marshaledJSON, nil
}

func matchesRegex(pattern, target string) bool {
	if pattern == "" {
		return true
	}
	matched, err := regexp.MatchString(pattern, target)
	if err != nil {
		// Assume it's not a match if an error occurs.
		return false
	}
	return matched
}

func getContainersList(containersList []*pb.Container, opts listOptions) []*pb.Container {
	filtered := []*pb.Container{}
	for _, c := range containersList {
		// Filter by pod name/namespace regular expressions.
		if matchesRegex(opts.nameRegexp, c.Metadata.Name) {
			filtered = append(filtered, c)
		}
	}

	sort.Sort(containerByCreated(filtered))
	n := len(filtered)
	if opts.latest {
		n = 1
	}
	if opts.last > 0 {
		n = opts.last
	}
	n = func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}(n, len(filtered))

	return filtered[:n]
}

func ListContainers(runtimeClient internalapi.RuntimeService, opts listOptions) error {
	filter := &pb.ContainerFilter{}
	if opts.id != "" {
		filter.Id = opts.id
	}
	if opts.podID != "" {
		filter.PodSandboxId = opts.podID
	}
	st := &pb.ContainerStateValue{}
	if !opts.all && opts.state == "" {
		st.State = pb.ContainerState_CONTAINER_RUNNING
		filter.State = st
	}
	if opts.state != "" {
		st.State = pb.ContainerState_CONTAINER_UNKNOWN
		switch strings.ToLower(opts.state) {
		case "created":
			st.State = pb.ContainerState_CONTAINER_CREATED
			filter.State = st
		case "running":
			st.State = pb.ContainerState_CONTAINER_RUNNING
			filter.State = st
		case "exited":
			st.State = pb.ContainerState_CONTAINER_EXITED
			filter.State = st
		case "unknown":
			st.State = pb.ContainerState_CONTAINER_UNKNOWN
			filter.State = st
		default:
			log.Fatalf("--state should be one of created, running, exited or unknown")
		}
	}
	if opts.latest || opts.last > 0 {
		// Do not filter by state if latest/last is specified.
		filter.State = nil
	}
	if opts.labels != nil {
		filter.LabelSelector = opts.labels
	}

	r, err := runtimeClient.ListContainers(context.TODO(), filter)
	// logrus.Debugf("ListContainerResponse: %v", r)
	if err != nil {
		return err
	}
	r = getContainersList(r, opts)

	switch opts.output {
	case "json":
		return outputProtobufObjAsJSON(&pb.ListContainersResponse{Containers: r})
	case "table":
	// continue; output will be generated after the switch block ends.
	default:
		return fmt.Errorf("unsupported output format %q", opts.output)
	}

	return nil
}

// ContainerStatus sends a ContainerStatusRequest to the server, and parses
// the returned ContainerStatusResponse.
func ContainerStatus(client internalapi.RuntimeService, id, output string, tmplStr string, quiet bool) error {
	verbose := !(quiet)
	if output == "" { // default to json output
		output = "json"
	}
	if id == "" {
		return fmt.Errorf("ID cannot be empty")
	}
	// request := &pb.ContainerStatusRequest{
	// 	ContainerId: id,
	// 	Verbose:     verbose,
	// }

	// logrus.Debugf("ContainerStatusRequest: %v", request)
	r, err := client.ContainerStatus(context.TODO(), id, verbose)
	// logrus.Debugf("ContainerStatusResponse: %v", r)
	if err != nil {
		return err
	}

	status, err := marshalContainerStatus(r.Status)
	if err != nil {
		return err
	}

	switch output {
	case "json", "go-template":
		return outputStatusInfo(status, r.Info, output, tmplStr)
	// case "table": // table output is after this switch block
	default:
		return fmt.Errorf("output option cannot be %s", output)
	}

	return nil
}

// marshalContainerStatus converts container status into string and converts
// the timestamps into readable format.
func marshalContainerStatus(cs *pb.ContainerStatus) (string, error) {
	statusStr, err := protobufObjectToJSON(cs)
	if err != nil {
		return "", err
	}
	jsonMap := make(map[string]interface{})
	err = json.Unmarshal([]byte(statusStr), &jsonMap)
	if err != nil {
		return "", err
	}

	jsonMap["createdAt"] = time.Unix(0, cs.CreatedAt).Format(time.RFC3339Nano)
	var startedAt, finishedAt time.Time
	if cs.State != pb.ContainerState_CONTAINER_CREATED {
		// If container is not in the created state, we have tried and
		// started the container. Set the startedAt.
		startedAt = time.Unix(0, cs.StartedAt)
	}
	if cs.State == pb.ContainerState_CONTAINER_EXITED ||
		(cs.State == pb.ContainerState_CONTAINER_UNKNOWN && cs.FinishedAt > 0) {
		// If container is in the exit state, set the finishedAt.
		// Or if container is in the unknown state and FinishedAt > 0, set the finishedAt
		finishedAt = time.Unix(0, cs.FinishedAt)
	}
	jsonMap["startedAt"] = startedAt.Format(time.RFC3339Nano)
	jsonMap["finishedAt"] = finishedAt.Format(time.RFC3339Nano)
	return marshalMapInOrder(jsonMap, *cs)
}

func outputStatusInfo(status string, info map[string]string, format string, tmplStr string) error {
	// Sort all keys
	keys := []string{}
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	jsonInfo := "{" + "\"status\":" + status + ","
	for _, k := range keys {
		var res interface{}
		// We attempt to convert key into JSON if possible else use it directly
		if err := json.Unmarshal([]byte(info[k]), &res); err != nil {
			jsonInfo += "\"" + k + "\"" + ":" + "\"" + info[k] + "\","
		} else {
			jsonInfo += "\"" + k + "\"" + ":" + info[k] + ","
		}
	}
	jsonInfo = jsonInfo[:len(jsonInfo)-1]
	jsonInfo += "}"

	switch format {
	case "json":
		var output bytes.Buffer
		if err := json.Indent(&output, []byte(jsonInfo), "", "  "); err != nil {
			return err
		}
		fmt.Println(output.String())
	default:
		fmt.Printf("Don't support %q format\n", format)
	}
	return nil
}

// marshalMapInOrder marshalls a map into json in the order of the original
// data structure.
func marshalMapInOrder(m map[string]interface{}, t interface{}) (string, error) {
	s := "{"
	v := reflect.ValueOf(t)
	for i := 0; i < v.Type().NumField(); i++ {
		field := jsonFieldFromTag(v.Type().Field(i).Tag)
		if field == "" || field == "-" {
			continue
		}
		value, err := json.Marshal(m[field])
		if err != nil {
			return "", err
		}
		s += fmt.Sprintf("%q:%s,", field, value)
	}
	s = s[:len(s)-1]
	s += "}"
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// jsonFieldFromTag gets json field name from field tag.
func jsonFieldFromTag(tag reflect.StructTag) string {
	field := strings.Split(tag.Get("json"), ",")[0]
	for _, f := range strings.Split(tag.Get("protobuf"), ",") {
		if !strings.HasPrefix(f, "json=") {
			continue
		}
		field = strings.TrimPrefix(f, "json=")
	}
	return field
}
