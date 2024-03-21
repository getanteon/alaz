package logstreamer

import (
	"bufio"
	"bytes"
	"context"
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

	"github.com/ddosify/alaz/cri"
	"github.com/fsnotify/fsnotify"
)

type LogStreamer struct {
	critool *cri.CRITool

	connPool *channelPool
	watcher  *fsnotify.Watcher

	logPathToFile          map[string]*fileReader
	logPathToContainerMeta map[string]string
	containerIdToLogPath   map[string]string

	done chan struct{}
}

type fileReader struct {
	mu sync.Mutex
	*bufio.Reader
}

func NewLogStreamer(ctx context.Context, critool *cri.CRITool) *LogStreamer {
	ls := &LogStreamer{
		critool: critool,
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
	ls.connPool = connPool

	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create connection pool")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to create fsnotify watcher")
	}
	ls.watcher = watcher

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		watcher.Close()
		connPool.Close()
		close(done)
	}()

	ls.logPathToFile = make(map[string]*fileReader, 0)
	ls.logPathToContainerMeta = make(map[string]string, 0)
	ls.containerIdToLogPath = make(map[string]string, 0)

	return ls
}

func (ls *LogStreamer) Done() chan struct{} {
	return ls.done
}

func (ls *LogStreamer) watchContainer(id string, name string) error {
	logPath, err := ls.critool.GetLogPath(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get log path for container %s", id)
		return err
	}

	_, err = ls.readerForLogPath(logPath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get reader for log path %s", logPath)
		return err
	}

	err = ls.watcher.Add(logPath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
		return err
	}
	ls.containerIdToLogPath[id] = logPath

	fileName := filepath.Base(logPath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	suffixNum, err := strconv.Atoi(fileNameWithoutExt)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to parse numeric part of log file name %s", fileName)
	}

	resp, err := ls.critool.ContainerStatus(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get container status for container %s", id)
		return err
	}

	ls.logPathToContainerMeta[logPath] = getContainerMetadataLine(resp.PodNs, resp.PodName, resp.PodUid, name, suffixNum)
	return nil
}

func (ls *LogStreamer) sendLogs(logPath string) error {
	var err error
	var poolConn *PoolConn = nil

	t := 1
	for {
		poolConn, err = ls.connPool.Get()
		if err != nil {
			log.Logger.Error().Err(err).Msgf("connect failed, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		if poolConn == nil {
			log.Logger.Info().Msgf("poolConn is nil, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		break
	}

	defer func() {
		if poolConn != nil && poolConn.unusable {
			log.Logger.Info().Msgf("connection is unusable, closing..")
			err := poolConn.Close()
			if err != nil {
				log.Logger.Error().Err(err).Msgf("Failed to close connection")
			}
		}
	}()

	// send metadata first
	metaLine := ls.logPathToContainerMeta[logPath]
	_, err = io.Copy(poolConn, bytes.NewBufferString(metaLine))
	if err != nil {
		log.Logger.Error().Err(err).Msgf("metadata could not be sent to backend: %v", err)
		poolConn.MarkUnusable()
		return err
	}

	// send logs
	reader, ok := ls.logPathToFile[logPath]
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

func (ls *LogStreamer) unwatchContainer(id string) {
	logPath := ls.containerIdToLogPath[id]
	log.Logger.Info().Msgf("removing container: %s, %s", id, logPath)

	// we must read until EOF and then remove the reader
	// otherwise the last logs may be lost
	// trigger manually
	ls.sendLogs(logPath)
	log.Logger.Info().Msgf("manually read for last time for %s", logPath)

	ls.watcher.Remove(logPath)

	// close reader
	if reader, ok := ls.logPathToFile[logPath]; ok {
		reader.Reset(nil)
		delete(ls.logPathToFile, logPath)
	}

	delete(ls.logPathToContainerMeta, logPath)
	delete(ls.containerIdToLogPath, id)
}

func (ls *LogStreamer) readerForLogPath(logPath string) (*fileReader, error) {
	if reader, ok := ls.logPathToFile[logPath]; ok {
		return reader, nil
	}

	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	file.Seek(0, io.SeekEnd) // seek to end of file
	reader := bufio.NewReader(file)
	ls.logPathToFile[logPath] = &fileReader{
		mu:     sync.Mutex{},
		Reader: reader,
	}

	return ls.logPathToFile[logPath], nil
}

func (ls *LogStreamer) StreamLogs() error {
	containers, err := ls.critool.GetAllContainers()
	if err != nil {
		return err
	}
	log.Logger.Info().Msg("watching containers")

	for _, c := range containers {
		err := ls.watchContainer(c.Id, c.Metadata.Name)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to watch container %s, %s", c.Id, c.Metadata.Name)
		}
	}

	// listen for new containers
	go func() {
		// poll every 10 seconds
		for {
			time.Sleep(10 * time.Second)

			containers, err := ls.critool.GetAllContainers()
			if err != nil {
				log.Logger.Error().Err(err).Msgf("Failed to get all containers")
				continue
			}

			// current containers that are being watched
			currentContainerIds := make(map[string]struct{}, 0)
			for id, _ := range ls.containerIdToLogPath {
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
					err := ls.watchContainer(c.Id, c.Metadata.Name)
					if err != nil {
						log.Logger.Error().Err(err).Msgf("Failed to watch new container %s, %s", c.Id, c.Metadata.Name)
					}
				}
			}

			for id := range currentContainerIds {
				if _, ok := aliveContainers[id]; !ok {
					// container is gone
					ls.unwatchContainer(id)
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
					case event, ok := <-ls.watcher.Events:
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

							err = ls.watcher.Add(logPath)
							if err != nil {
								log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
								continue
							}
							logFile.Seek(0, io.SeekEnd) // seek to end of file
							ls.logPathToFile[logPath] = &fileReader{
								mu:     sync.Mutex{},
								Reader: bufio.NewReader(logFile),
							}

							log.Logger.Info().Msgf("reopened file for rename: %s", logPath)
							continue
						} else if event.Has(fsnotify.Write) {
							// TODO: apps that writes too much logs might block small applications and causes lag on small apps logs
							// we don't have to read logs on every write event ??

							err := ls.sendLogs(event.Name)
							if err != nil {
								log.Logger.Error().Err(err).Msgf("Failed to send logs for %s", event.Name)
							}
						}
					case err, ok := <-ls.watcher.Errors:
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

// podUid
// containerName
// which version of container, 0,1,2...
func getContainerMetadataLine(podNs, podName, podUid, containerName string, num int) string {
	return fmt.Sprintf("**AlazLogs_%s_%s_%s_%s_%d**\n", podNs, podName, podUid, containerName, num)
}
