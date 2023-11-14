// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"context"
	"net"
	"sync"

	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/rs/zerolog"
)

// Derived from netutil.LimitListener but works slightly differently.
// Instead of blocking on the semaphore before acception connection,
// this implementation immediately accepts connections and if cannot
// acquire the semaphore it forces the connection closed.
// Ideally, this limiter is run *before* the TLS handshake occurs
// to prevent DDOS attack that eats all the server's CPU.
// The downside to this is that it will Close() valid connections
// indiscriminately.

func Listener(l net.Listener, n int) net.Listener {
	return &limitListener{
		Listener: l,
		sem:      make(chan struct{}, n),
		done:     make(chan struct{}),
	}
}

type limitListener struct {
	net.Listener
	sem       chan struct{}
	closeOnce sync.Once     // ensures the done chan is only closed once
	done      chan struct{} // no values sent; closed when Close is called
}

func (l *limitListener) acquire() bool {
	select {
	case <-l.done:
		return false
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}
func (l *limitListener) release() { <-l.sem }

func (l *limitListener) Accept() (net.Conn, error) {

	// Accept the connection irregardless
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// If we cannot acquire the semaphore, close the connection
	if acquired := l.acquire(); !acquired {
		zlog := zerolog.Ctx(context.TODO()).Warn()

		var err error
		if c != nil {
			err = c.Close()
			zlog.Str(logger.ECSServerAddress, c.LocalAddr().String())
			zlog.Str(logger.ECSClientAddress, c.RemoteAddr().String())
			zlog.Err(err)
		}
		zlog.Int("max", cap(l.sem)).Msg("Connection closed due to max limit")

		return c, nil
	}

	return &limitListenerConn{Conn: c, release: l.release}, nil
}

func (l *limitListener) Close() error {
	err := l.Listener.Close()
	l.closeOnce.Do(func() { close(l.done) })
	return err
}

type limitListenerConn struct {
	net.Conn
	releaseOnce sync.Once
	release     func()
}

func (l *limitListenerConn) Close() error {
	err := l.Conn.Close()
	l.releaseOnce.Do(l.release)
	return err
}
