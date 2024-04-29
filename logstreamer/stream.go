package logstreamer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"k8s.io/apimachinery/pkg/util/uuid"

	"github.com/ddosify/alaz/cri"
	"github.com/fsnotify/fsnotify"
)

type LogStreamer struct {
	critool *cri.CRITool

	connPool *channelPool
	watcher  *fsnotify.Watcher

	readerMapMu   sync.RWMutex
	logPathToFile map[string]*fileReader

	metaMapMu              sync.RWMutex
	logPathToContainerMeta map[string]string

	idToPathMu           sync.RWMutex
	containerIdToLogPath map[string]string

	ctx  context.Context
	done chan struct{}

	maxConnection int
}

type fileReader struct {
	mu *sync.Mutex
	*bufio.Reader
}

func createTLSConfig() (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	caCert := []byte(CaCert)
	caCertPool.AppendCertsFromPEM(caCert)

	serverName := os.Getenv("LOG_BACKEND_SERVER_NAME")
	if serverName == "" {
		serverName = "log-alaz-staging.getanteon.com"
	}

	return &tls.Config{
		RootCAs:    caCertPool,
		ServerName: serverName,
	}, nil
}

func createFsNotifyWatcher() (*fsnotify.Watcher, error) {
	var sz uint = 1000
	return fsnotify.NewBufferedWatcher(sz)
}

func NewLogStreamer(ctx context.Context, critool *cri.CRITool) (*LogStreamer, error) {
	ls := &LogStreamer{
		critool: critool,
	}

	logBackend := os.Getenv("LOG_BACKEND")
	if logBackend == "" {
		logBackend = "log-backend.ddosify:8282"
	}

	dialer := &net.Dialer{
		Timeout: 60 * time.Second,
	}

	tlsConfig, err := createTLSConfig()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to create TLS config")
		return nil, err
	}

	max_connection := 30
	max_connection_str := os.Getenv("LOG_BACKEND_MAX_CONNECTION")
	if max_connection_str != "" {
		m, err := strconv.Atoi(max_connection_str)
		if err == nil {
			max_connection = m
		}
	}

	connPool, err := NewChannelPool(5, max_connection, func() (*tls.Conn, error) {
		log.Logger.Info().Msgf("dialing to log backend: %s", logBackend)
		return tls.DialWithDialer(dialer, "tcp", logBackend, tlsConfig)
		// return tls.Dial("tcp", logBackend, tlsConfig)
	})
	ls.connPool = connPool
	ls.maxConnection = max_connection

	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	watcher, err := createFsNotifyWatcher()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to create fsnotify watcher")
		return nil, err
	}

	ls.watcher = watcher
	ls.ctx = ctx
	ls.done = make(chan struct{})
	go func() {
		<-ctx.Done()
		ls.watcher.Close()
		ls.connPool.Close()
		close(ls.done)
	}()

	ls.readerMapMu = sync.RWMutex{}
	ls.logPathToFile = make(map[string]*fileReader, 0)
	ls.logPathToContainerMeta = make(map[string]string, 0)
	ls.containerIdToLogPath = make(map[string]string, 0)

	return ls, nil
}

func (ls *LogStreamer) Done() chan struct{} {
	return ls.done
}

func (ls *LogStreamer) watchContainer(id string, name string, new bool) error {
	resp, err := ls.critool.ContainerStatus(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get container status for container [%s]", id)
		return err
	}

	if ls.critool.FilterNamespace(resp.PodNs) {
		log.Logger.Debug().Msgf("Skipping logs for container [%s] with id [%s]", name, id)
		return nil
	}

	logPath, err := ls.critool.GetLogPath(id)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get log path for container %s", id)
		return err
	}

	self := false
	if strings.HasPrefix(name, "alaz-") {
		self = true
		return nil
	}

	_, err = ls.readerForLogPath(logPath, new || self)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to get reader for log path %s", logPath)
		return err
	}

	err = ls.watcher.Add(logPath)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to add log path %s to watcher", logPath)
		return err
	}
	ls.idToPathMu.Lock()
	ls.containerIdToLogPath[id] = logPath
	ls.idToPathMu.Unlock()

	fileName := filepath.Base(logPath)
	fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	suffixNum, err := strconv.Atoi(fileNameWithoutExt)
	if err != nil {
		log.Logger.Error().Err(err).Msgf("Failed to parse numeric part of log file name %s", fileName)
	}

	ls.metaMapMu.Lock()
	ls.logPathToContainerMeta[logPath] = getContainerMetadataLine(resp.PodNs, resp.PodName, resp.PodUid, name, suffixNum)
	ls.metaMapMu.Unlock()
	return nil
}

func (ls *LogStreamer) sendLogs(logPath string, id string) error {
	var err error
	var poolConn *PoolConn = nil

	// id := string(uuid.NewUUID())
	log.Logger.Info().Str("uuid", id).Msgf("consumed logs for %s", logPath)

	t := 1
	for {
		poolConn, err = ls.connPool.Get()
		if err != nil {
			log.Logger.Error().Str("uuid", id).Err(err).Msgf("connect failed, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		if poolConn == nil {
			log.Logger.Info().Str("uuid", id).Msgf("poolConn is nil, retryconn..")
			time.Sleep(time.Duration(t) * time.Second)
			t *= 2
			continue
		}
		break
	}
	log.Logger.Info().Str("uuid", id).Msgf("got connection from pool %s", logPath)

	// defer func() {
	// 	if poolConn != nil && poolConn.unusable {
	// 		log.Logger.Info().Msgf("connection is unusable, closing..")
	// 		err := poolConn.Close()
	// 		if err != nil {
	// 			log.Logger.Error().Err(err).Msgf("Failed to close connection")
	// 		}
	// 	}
	// }()

	// send logs
	log.Logger.Info().Str("uuid", id).Msgf("before ls.readerMapMu.RLock() %s", logPath)
	ls.readerMapMu.RLock()
	reader, ok := ls.logPathToFile[logPath]
	ls.readerMapMu.RUnlock()
	log.Logger.Info().Str("uuid", id).Msgf("after ls.readerMapMu.RUnLock() %s", logPath)
	if !ok || reader == nil {
		log.Logger.Error().Str("uuid", id).Msgf("reader for log path %s is not found", logPath)
		poolConn.Close() // put back, it will close underlying connection
		return err
	}

	log.Logger.Info().Str("uuid", id).Msgf("before reader.mu.Lock() %s", logPath)
	reader.mu.Lock() // readeri alamiyo ?
	log.Logger.Info().Str("uuid", id).Msgf("after reader.mu.Lock() %s", logPath)

	// send metadata first
	ls.metaMapMu.RLock()
	log.Logger.Info().Str("uuid", id).Msgf("after ls.metaMapMu.RLock() %s", logPath)

	metaLine, ok := ls.logPathToContainerMeta[logPath]
	ls.metaMapMu.RUnlock()
	log.Logger.Info().Str("uuid", id).Msgf("after ls.metaMapMu.RUnlock() %s", logPath)

	if !ok {
		log.Logger.Warn().Str("uuid", id).Msgf("metadata for log path %s is not found", logPath)
		reader.mu.Unlock()
		poolConn.Close() // put back, it will close underlying connection
		return nil
	}

	log.Logger.Info().Str("uuid", id).Msgf("copying metadata %s", logPath)
	_, err = io.Copy(poolConn, bytes.NewBufferString(metaLine))
	if err != nil {
		log.Logger.Error().Str("uuid", id).Err(err).Msgf("metadata could not be sent to backend: %v", err)
		poolConn.MarkUnusable()
		poolConn.Close() // put back, it will close underlying connection
		reader.mu.Unlock()
		return err
	}
	log.Logger.Info().Str("uuid", id).Msgf("copied metadata %s", logPath)

	_, err = io.Copy(poolConn, reader)
	if err != nil {
		log.Logger.Error().Str("uuid", id).Err(err).Msgf("logs could not be sent to backend: %v", err)
		poolConn.MarkUnusable()
		poolConn.Close() // put back, it will close underlying connection
		reader.mu.Unlock()
		return err
	} else {
		log.Logger.Info().Str("uuid", id).Msgf("logs sent to backend for %s", logPath)
	}
	reader.mu.Unlock()
	log.Logger.Info().Str("uuid", id).Msgf("after reader.mu.Unlock() %s", logPath)

	// put the connection back to the pool, closes if unusable
	poolConn.Close()
	log.Logger.Info().Str("uuid", id).Msgf("after poolConn.Close() %s", logPath)

	return nil
}

func (ls *LogStreamer) unwatchContainer(id string) {
	ls.idToPathMu.RLock()
	logPath := ls.containerIdToLogPath[id]
	ls.idToPathMu.RUnlock()
	log.Logger.Info().Msgf("removing container: %s, %s", id, logPath)

	// we must read until EOF and then remove the reader
	// otherwise the last logs may be lost
	// trigger manually, container runtime still can add some latest logs after deletion
	// wait for 1 second to ensure all logs are read
	time.Sleep(1 * time.Second)
	uid := string(uuid.NewUUID())
	ls.sendLogs(logPath, uid)
	log.Logger.Info().Msgf("manually read for last time for %s", logPath)

	ls.watcher.Remove(logPath)

	// close reader
	ls.readerMapMu.Lock()
	if _, ok := ls.logPathToFile[logPath]; ok {
		delete(ls.logPathToFile, logPath)
	}
	ls.readerMapMu.Unlock()

	ls.metaMapMu.Lock()
	delete(ls.logPathToContainerMeta, logPath)
	ls.metaMapMu.Unlock()

	ls.idToPathMu.Lock()
	delete(ls.containerIdToLogPath, id)
	ls.idToPathMu.Unlock()
}

func (ls *LogStreamer) readerForLogPath(logPath string, new bool) (*fileReader, error) {
	ls.readerMapMu.RLock()
	if reader, ok := ls.logPathToFile[logPath]; ok {
		ls.readerMapMu.RUnlock()
		return reader, nil
	}
	ls.readerMapMu.RUnlock()

	file, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}

	// this container was alive before alaz installation, seek to end of file
	if !new {
		file.Seek(0, io.SeekEnd) // seek to end of file
	}

	reader := bufio.NewReader(file)

	ls.readerMapMu.Lock()
	r := &fileReader{
		mu:     &sync.Mutex{},
		Reader: reader,
	}
	ls.logPathToFile[logPath] = r
	ls.readerMapMu.Unlock()

	return r, nil
}

func (ls *LogStreamer) watchContainers() error {
	containers, err := ls.critool.GetAllContainers()
	if err != nil {
		return err
	}
	for _, c := range containers {
		err := ls.watchContainer(c.Id, c.Metadata.Name, false)
		if err != nil {
			log.Logger.Error().Err(err).Msgf("Failed to watch container %s, %s", c.Id, c.Metadata.Name)
		}
	}
	return nil
}

func (ls *LogStreamer) StreamLogs() error {
	log.Logger.Info().Msg("watching containers")
	err := ls.watchContainers()
	if err != nil {
		log.Logger.Error().Err(err).Msg("failed to watch containers")
		return err
	}

	// listen for new containers
	go func() {
		// poll every 10 seconds
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ls.ctx.Done():
				log.Logger.Info().Msg("context done, stopping container watcher")
				return
			case <-t.C:
				containers, err := ls.critool.GetAllContainers()
				if err != nil {
					log.Logger.Error().Err(err).Msgf("Failed to get all containers")
					continue
				}

				// current containers that are being watched
				currentContainerIds := make(map[string]struct{}, 0)
				ls.idToPathMu.RLock()
				for id, _ := range ls.containerIdToLogPath {
					currentContainerIds[id] = struct{}{}
				}
				ls.idToPathMu.RUnlock()

				aliveContainers := make(map[string]struct{}, 0)

				for _, c := range containers {
					aliveContainers[c.Id] = struct{}{}
					if _, ok := currentContainerIds[c.Id]; ok {
						continue
					} else {
						// new container
						log.Logger.Debug().Msgf("new container found: %s, %s", c.Id, c.Metadata.Name)
						err := ls.watchContainer(c.Id, c.Metadata.Name, true)
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

		}
	}()

	mu := sync.RWMutex{}
	lastSendTimeMap := make(map[string]time.Time, 0)

	mu2 := sync.RWMutex{}
	lastSkippedWriteEventTimeMap := make(map[string]time.Time, 0)

	workerCount := ls.maxConnection

	// workers will listen for log events and send logs
	logPathChan := make(chan string, 1000)

	// flush
	// if a log event came but did not trigger and sendLogs, we need to flush it after some time
	go func() {
		t := time.NewTicker(10 * time.Second)
		for {
			select {
			case <-ls.ctx.Done():
				log.Logger.Info().Msg("context done, stopping flusher")
				return
			case <-t.C:
				mu2.RLock()
				for logPath, lastSkippedWriteTime := range lastSkippedWriteEventTimeMap {
					// check lastSendTimeMap
					mu.RLock()
					lastSendTime, ok := lastSendTimeMap[logPath]
					mu.RUnlock()
					if ok && (lastSkippedWriteTime.Sub(lastSendTime) > 2*time.Second) {
						logPathChan <- logPath
						log.Logger.Info().Msgf("flushing logs for %s", logPath)
					}
				}
				mu2.RUnlock()
			}
		}
	}()

	// start workers to send logs
	go func() {
		for i := 0; i < workerCount; i++ {
			go func() {
				for logPath := range logPathChan {
					uid := string(uuid.NewUUID())
					log.Logger.Info().Str("uuid", uid).Msgf("sendLogs called...: %s", logPath)
					err := ls.sendLogs(logPath, uid)
					log.Logger.Info().Str("uuid", uid).Msgf("sendLogs returned...: %s", logPath)
					if err != nil {
						log.Logger.Error().Err(err).Str("uuid", uid).Msgf("Failed to send logs for %s", logPath)
					} else {
						mu.Lock()
						lastSendTimeMap[logPath] = time.Now()
						mu.Unlock()
					}
				}
				log.Logger.Warn().Msg("logPathChan closed, stopping worker")
			}()
		}
	}()

	// start listening for fsnotify events and publish log events to logPathChan
	go func() {
		initialTimeWindow := 2 * time.Second
		restartCh := make(chan struct{}, 1)
		fsNotifyWorker := func(restartCh chan struct{}) {
			timeWindow := initialTimeWindow
			var lastChanFullTime time.Time
			go func() {
				t := time.NewTicker(10 * time.Second)
				for {
					select {
					case <-ls.ctx.Done():
						return
					case <-t.C:
						if time.Since(lastChanFullTime) > 1*time.Minute && timeWindow > initialTimeWindow {
							timeWindow = initialTimeWindow
						}
					}
				}
			}()
			c := 0
			for {
				select {
				case <-ls.ctx.Done():
					log.Logger.Info().Msg("context done, stopping fsnotify worker")
					return
				case event, ok := <-ls.watcher.Events:
					if !ok {
						log.Logger.Info().Msg("fsnotify events channel closed")
						return
					}
					c++
					if c%10 == 0 {
						log.Logger.Info().Msgf("fsnotify event: %s", event)
					}
					logPath := event.Name
					if logPath == "" {
						log.Logger.Warn().Str("op", event.Op.String()).Msgf("empty log path from fsnotify")
						continue
					}
					if event.Has(fsnotify.Rename) { // logrotate case
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
						ls.readerMapMu.Lock()
						r, ok := ls.logPathToFile[logPath]
						if ok {
							r.Reader = bufio.NewReader(logFile)
						} else {
							ls.logPathToFile[logPath] = &fileReader{
								mu:     &sync.Mutex{},
								Reader: bufio.NewReader(logFile),
							}
						}
						ls.readerMapMu.Unlock()

						log.Logger.Info().Msgf("reopened file for rename: %s", logPath)
						continue
					} else if event.Has(fsnotify.Write) {
						// When too many write events come from fsnotify
						// and waits unprocessed, inotify buffer overflows
						// to prevent this, we skip some write events that happens frequently
						mu.RLock()
						lastSendTime, ok := lastSendTimeMap[logPath]
						mu.RUnlock()

						// if a log data is sent in the last 2 seconds, skip this one
						if ok && time.Since(lastSendTime) < timeWindow {
							mu2.Lock()
							lastSkippedWriteEventTimeMap[logPath] = time.Now()
							mu2.Unlock()
							continue
						}

						log.Logger.Info().Msgf("logPath sending...: %s", logPath)
						select {
						case logPathChan <- logPath:
							log.Logger.Info().Msgf("logPathChan sent to chan: %s", logPath)
						default:
							log.Logger.Info().Msgf("logPath fail...: %s", logPath)

							// increase timeWindow to prevent frequent writes
							if timeWindow < 10*time.Second { // upperlimit
								// log.Logger.Warn().Msgf("logPathChan is full, increasing timeWindow to %s", timeWindow.String())
								timeWindow *= 2
							}
							mu2.Lock()
							lastSkippedWriteEventTimeMap[logPath] = time.Now()
							mu2.Unlock()
							lastChanFullTime = time.Now()
						}
					}
				case err, ok := <-ls.watcher.Errors:
					if !ok {
						log.Logger.Info().Msg("fsnotify errors channel closed")
						return
					}
					log.Logger.Error().Err(err).Msgf("fsnotify error")
					// watcher stops working on fsnotify: queue or buffer overflow
					// we need to recreate the watcher
					ls.watcher.Close()
					restartCh <- struct{}{}
				}
			}
		}

		startFsnotifyWorkers := func() {
			// start workers
			for i := 0; i < workerCount; i++ {
				go fsNotifyWorker(restartCh)
			}
		}

		go func() {
			for {
				select {
				case <-ls.ctx.Done():
					return
				case <-restartCh:
					log.Logger.Warn().Msg("restarting fsnotify watcher")
					watcher, err := createFsNotifyWatcher()
					if err != nil {
						log.Logger.Error().Err(err).Msg("failed to recreate fsnotify watcher")
						return
					}
					ls.watcher = watcher
					err = ls.watchContainers()
					if err != nil {
						log.Logger.Error().Err(err).Msg("failed to watch containers on watcher restart")
						return
					}

					// start workers
					log.Logger.Info().Msg("restarting fsnotify workers after watcher recreation")
					go startFsnotifyWorkers()
				}
			}
		}()

		go startFsnotifyWorkers()

	}()

	return nil
}

// podUid
// containerName
// which version of container, 0,1,2...
func getContainerMetadataLine(podNs, podName, podUid, containerName string, num int) string {
	return fmt.Sprintf("\n**AlazLogs_%s_%s_%s_%s_%d**\n", podNs, podName, podUid, containerName, num)
}
