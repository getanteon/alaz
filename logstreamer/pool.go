package logstreamer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ddosify/alaz/log"
)

var ErrClosed = errors.New("pool is closed")

type PoolConn struct {
	net.Conn
	mu       sync.RWMutex
	c        *channelPool
	unusable bool
	tls      bool
}

func (p *PoolConn) isAlive() bool {
	var buf [1]byte
	p.SetReadDeadline(time.Now().Add(1 * time.Millisecond)) // Set a very short deadline
	_, err := p.Read(buf[:])

	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			// Timeout occurred, but connection is still alive
			return true
		}
		// Real error or EOF encountered, connection likely dead
		return false
	}

	if buf[0] == 'X' {
		// close
		return false
	}

	// Data received (unexpected in send only), process or ignore
	return true
}

// Close() puts the given connects back to the pool instead of closing it.
func (p *PoolConn) Close() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.unusable {
		if p.Conn != nil {
			log.Logger.Info().Msg("connection is unusable, closing it")
			if p.tls {
				return p.Conn.(*tls.Conn).Close()
			} else {
				return p.Conn.Close()
			}
		}
		return nil
	}
	return p.c.put(p)
}

// MarkUnusable() marks the connection not usable any more, to let the pool close it instead of returning it to pool.
func (p *PoolConn) MarkUnusable() {
	p.mu.Lock()
	p.unusable = true
	p.mu.Unlock()
}

// newConn wraps a standard net.Conn to a poolConn net.Conn.
func (c *channelPool) wrapConn(conn net.Conn) *PoolConn {
	p := &PoolConn{c: c}
	p.Conn = conn
	p.tls = c.tls
	return p
}

type channelPool struct {
	// storage for our net.Conn connections
	mu    sync.RWMutex
	conns chan *PoolConn

	// net.Conn generator
	factory Factory
	tls     bool
}

func (c *channelPool) getConnsAndFactory() (chan *PoolConn, Factory) {
	c.mu.RLock()
	conns := c.conns
	factory := c.factory
	c.mu.RUnlock()
	return conns, factory
}

// Get implements the Pool interfaces Get() method. If there is no new
// connection available in the pool, a new connection will be created via the
// Factory() method.
func (c *channelPool) Get() (*PoolConn, error) {
	conns, factory := c.getConnsAndFactory()
	if conns == nil {
		return nil, ErrClosed
	}

	// wrap our connections with out custom net.Conn implementation (wrapConn
	// method) that puts the connection back to the pool if it's closed.
	select {
	case conn := <-conns:
		if conn == nil {
			return nil, fmt.Errorf("connection is nil")
		}
		if conn.unusable {
			log.Logger.Info().Msg("connection is unusable on Get, closing it")
			conn.Close()
			return nil, fmt.Errorf("connection is unusable")
		}

		if conn.isAlive() {
			return conn, nil
		} else {
			conn.MarkUnusable()
			conn.Close()
			return nil, fmt.Errorf("connection is dead")
		}
	default:
		conn, err := factory()
		if err != nil {
			return nil, err
		}
		log.Logger.Info().Msg("no connection available, created a new one")
		return c.wrapConn(conn), nil
	}
}

// put puts the connection back to the pool. If the pool is full or closed,
// conn is simply closed. A nil conn will be rejected.
func (c *channelPool) put(conn *PoolConn) error {
	if conn == nil {
		return errors.New("connection is nil. rejecting")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.conns == nil {
		// pool is closed, close passed connection
		return conn.Close()
	}

	// put the resource back into the pool. If the pool is full, this will
	// block and the default case will be executed.
	select {
	case c.conns <- conn:
		// log.Logger.Info().Msg("putting connection back into the pool")
		return nil
	default:
		// pool is full, close passed connection
		log.Logger.Info().Msg("pool is full, close passed connection")
		return conn.Close()
	}
}

func (c *channelPool) Close() {
	c.mu.Lock()
	conns := c.conns
	c.conns = nil
	c.factory = nil
	c.mu.Unlock()

	if conns == nil {
		return
	}

	close(conns)
	for conn := range conns {
		conn.Close()
	}
}

func (c *channelPool) Len() int {
	conns, _ := c.getConnsAndFactory()
	return len(conns)
}

func NewChannelPool(initialCap, maxCap int, factory Factory, isTls bool) (*channelPool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, errors.New("invalid capacity settings")
	}

	c := &channelPool{
		conns:   make(chan *PoolConn, maxCap),
		factory: factory,
		tls:     isTls,
	}

	// create initial connections, if something goes wrong,
	// just close the pool error out.
	for i := 0; i < initialCap; i++ {
		conn, err := factory()
		if err != nil {
			c.Close()
			return nil, fmt.Errorf("factory is not able to fill the pool: %s", err)
		}
		log.Logger.Debug().Msg("new connection created for log streaming")
		c.conns <- c.wrapConn(conn)
	}

	return c, nil
}

// Factory is a function to create new connections.
type Factory func() (net.Conn, error)
