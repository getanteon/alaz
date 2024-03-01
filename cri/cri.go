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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ddosify/alaz/log"
	"github.com/fsnotify/fsnotify" //nolint:staticcheck

	//nolint:staticcheck
	internalapi "k8s.io/cri-api/pkg/apis"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
	"k8s.io/kubernetes/pkg/kubelet/cri/remote"
)

// https://kubernetes.io/docs/setup/production-environment/container-runtimes/#cri-versions
var defaultRuntimeEndpoints = []string{"unix:///proc/1/root/run/containerd/containerd.sock", "unix:///proc/1/root/var/run/crio/crio.sock", "unix:///proc/1/root/run/cri-dockerd.sock"}

type fileReader struct {
	mu sync.Mutex
	*bufio.Reader
}

type containerPodInfo struct {
	podUid  string
	podName string
	podNs   string
}

type CRITool struct {
	rs internalapi.RuntimeService

	connPool *channelPool
	watcher  *fsnotify.Watcher

	logPathToFile          map[string]*fileReader
	logPathToContainerMeta map[string]string
	containerIdToLogPath   map[string]string

	done chan struct{}
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

	logBackend := os.Getenv("LOG_BACKEND")
	if logBackend == "" {
		logBackend = "log-backend.ddosify:8282"
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	connPool, err := NewChannelPool(5, 30, func() (net.Conn, error) {
		return dialer.Dial("tcp", logBackend)
	})

	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create connection pool")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create fsnotify watcher")
	}

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		watcher.Close()
		connPool.Close()
		close(done)
	}()

	logPathToFile := make(map[string]*fileReader, 0)
	logPathToContainerMeta := make(map[string]string, 0)
	containerIdToLogPath := make(map[string]string, 0)

	return &CRITool{
		rs:                     res,
		connPool:               connPool,
		watcher:                watcher,
		logPathToFile:          logPathToFile,
		logPathToContainerMeta: logPathToContainerMeta,
		containerIdToLogPath:   containerIdToLogPath,
		done:                   done,
	}, nil
}

func (ct *CRITool) Done() chan struct{} {
	return ct.done
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

func (ct *CRITool) containerStatus(id string) (*containerPodInfo, error) {
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

	return &containerPodInfo{
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

// podUid
// containerName
// which version of container, 0,1,2...
func getContainerMetadataLine(podNs, podName, podUid, containerName string, num int) string {
	return fmt.Sprintf("**AlazLogs_%s_%s_%s_%s_%d**\n", podNs, podName, podUid, containerName, num)
}

func (ct *CRITool) readerForLogPath(logPath string) (*fileReader, error) {
	if reader, ok := ct.logPathToFile[logPath]; ok {
		return reader, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	file.Seek(0, io.SeekEnd) // seek to end of file
	reader := bufio.NewReader(file)
	ct.logPathToFile[logPath] = &fileReader{
		mu:     sync.Mutex{},
		Reader: reader,
	}

	return ct.logPathToFile[logPath], nil
}

func (ct *CRITool) watchContainer(id string, name string) error {
	logPath, err := ct.getLogPath(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get log path for container %s", id)
		return err
	}

	_, err = ct.readerForLogPath(logPath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get reader for log path %s", logPath)
		return err
	}

	err = ct.watcher.Add(logPath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
		return err
	}
	ct.containerIdToLogPath[id] = logPath

	fileName := filepath.Base(logPath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	suffixNum, err := strconv.Atoi(fileNameWithoutExt)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to parse numeric part of log file name %s", fileName)
	}

	resp, err := ct.containerStatus(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get container status for container %s", id)
		return err
	}

	ct.logPathToContainerMeta[logPath] = getContainerMetadataLine(resp.podNs, resp.podName, resp.podUid, name, suffixNum)
	return nil
}

func (ct *CRITool) unwatchContainer(id string) {
	logPath := ct.containerIdToLogPath[id]
	log.Logger.Info().Msgf("removing container: %s, %s", id, logPath)

	// we must read until EOF and then remove the reader
	// otherwise the last logs may be lost
	// trigger manually
	ct.sendLogs(logPath)
	log.Logger.Info().Msgf("manually read for last time for %s", logPath)

	ct.watcher.Remove(logPath)

	// close reader
	if reader, ok := ct.logPathToFile[logPath]; ok {
		reader.Reset(nil)
		delete(ct.logPathToFile, logPath)
	}

	delete(ct.logPathToContainerMeta, logPath)
	delete(ct.containerIdToLogPath, id)
}

func (ct *CRITool) sendLogs(logPath string) error {
	var err error
	var poolConn *PoolConn = nil

	t := 1
	for {
		poolConn, err = ct.connPool.Get()
		if err != nil {
			log.Logger.Error().Err(err).Msgf("connect failed, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		if poolConn == nil {
			log.Logger.Error().Msgf("poolConn is nil, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		break
	}

	defer func() {
		if poolConn != nil && poolConn.unusable {
			log.Logger.Error().Msgf("connection is unusable, closing..")
			err := poolConn.Close()
			if err != nil {
				log.Logger.Error().Err(err).Msgf("Failed to close connection")
			}
		}
	}()

	// send metadata first
	metaLine := ct.logPathToContainerMeta[logPath]
	_, err = io.Copy(poolConn, bytes.NewBufferString(metaLine))
	if err != nil {
		log.Logger.Error().Err(err).Msgf("metadata could not be sent to backend: %v", err)
		poolConn.MarkUnusable()
		return err
	}

	// send logs
	reader, ok := ct.logPathToFile[logPath]
	if !ok || reader == nil {
		log.Logger.Error().Msgf("reader for log path %s is not found", logPath)
		return err
	}

	reader.mu.Lock()
	_, err = io.Copy(poolConn, reader)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("logs could not be sent to backend: %v", err)
		poolConn.MarkUnusable()
		reader.mu.Unlock()
		return err
	}
	reader.mu.Unlock()

	// put the connection back to the pool, closes if unusable
	poolConn.Close()
	return nil
}

func (ct *CRITool) StreamLogs() error {
	containers, err := ct.getAllContainers()
	if err != nil {
		return err
	}
	log.Logger.Info().Msg("watching containers")

	for _, c := range containers {
		err := ct.watchContainer(c.Id, c.Metadata.Name)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to watch container %s, %s", c.Id, c.Metadata.Name)
		}
	}

	// listen for new containers
	go func() {
		// poll every 10 seconds
		for {
			time.Sleep(10 * time.Second)

			containers, err := ct.getAllContainers()
			if err != nil {
				log.Logger.Error().Err(err).Msgf("Failed to get all containers")
				continue
			}

			// current containers that are being watched
			currentContainerIds := make(map[string]struct{}, 0)
			for id, _ := range ct.containerIdToLogPath {
				currentContainerIds[id] = struct{}{}
			}

			aliveContainers := make(map[string]struct{}, 0)

			for _, c := range containers {
				aliveContainers[c.Id] = struct{}{}
				if _, ok := currentContainerIds[c.Id]; ok {
					continue
				} else {
					// new container
					log.Logger.Info().Msgf("new container found: %s, %s", c.Id, c.Metadata.Name)
					err := ct.watchContainer(c.Id, c.Metadata.Name)
					if err != nil {
						log.Logger.Error().Err(err).Msgf("Failed to watch new container %s, %s", c.Id, c.Metadata.Name)
					}
				}
			}

			for id := range currentContainerIds {
				if _, ok := aliveContainers[id]; !ok {
					// container is gone
					ct.unwatchContainer(id)
				}
			}
		}
	}()

	// start listening for fsnotify events
	go func() {
		worker := 10
		// start workers
		for i := 0; i < worker; i++ {
			go func() {
				for {
					select {
					case event, ok := <-ct.watcher.Events:
						if !ok {
							return
						}

						if event.Has(fsnotify.Rename) { // logrotate case
							logPath := event.Name
							// containerd compresses logs, and recreates the file, it comes as a rename event
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

							err = ct.watcher.Add(logPath)
							if err != nil {
								log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
								continue
							}
							logFile.Seek(0, io.SeekEnd) // seek to end of file
							ct.logPathToFile[logPath] = &fileReader{
								mu:     sync.Mutex{},
								Reader: bufio.NewReader(logFile),
							}

							log.Logger.Info().Msgf("reopened file for rename: %s", logPath)
							continue
						} else if event.Has(fsnotify.Write) {
							// TODO: apps that writes too much logs might block small applications and causes lag on small apps logs
							// we don't have to read logs on every write event ??

							err := ct.sendLogs(event.Name)
							if err != nil {
								log.Logger.Error().Err(err).Msgf("Failed to send logs for %s", event.Name)
							}
						}
					case err, ok := <-ct.watcher.Errors:
						if !ok {
							return
						}
						log.Logger.Error().Err(err).Msgf("fsnotify error")
					}
				}
			}()
		}
	}()

	return nil
}
