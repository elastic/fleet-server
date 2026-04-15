// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

const defaultDebounceDelay = 5 * time.Second

// CertReloader watches TLS certificate and key files on disk and atomically
// reloads them when changes are detected. It exposes a GetCertificate callback
// suitable for use with tls.Config.GetCertificate.
type CertReloader struct {
	certPath string
	keyPath  string
	debounce time.Duration
	// cert is accessed atomically because GetCertificate is called from TLS
	// handshake goroutines while Run stores new certs from the fsnotify goroutine.
	cert atomic.Pointer[tls.Certificate]
}

// Option is a functional option for configuring a CertReloader.
type Option func(*CertReloader)

// WithDebounce sets the debounce delay for the file watcher. If not specified,
// a default of 5 seconds is used.
func WithDebounce(d time.Duration) Option {
	return func(r *CertReloader) {
		r.debounce = d
	}
}

// New creates a CertReloader for the given cert and key file paths. It performs
// an initial load of the certificate, returning an error if the initial load
// fails.
func New(certPath, keyPath string, opts ...Option) (*CertReloader, error) {
	if certPath == "" || keyPath == "" {
		return nil, fmt.Errorf("certificate and key paths must be non-empty")
	}

	r := &CertReloader{
		certPath: certPath,
		keyPath:  keyPath,
		debounce: defaultDebounceDelay,
	}
	for _, opt := range opts {
		opt(r)
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("initial certificate load failed: %w", err)
	}
	r.cert.Store(&cert)

	return r, nil
}

// GetCertificate returns the current certificate. It is safe for concurrent use
// and is intended to be assigned to tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

// Run starts the file watcher and debounced reload loop. It blocks until the
// context is cancelled. On context cancellation, the watcher is closed and Run
// returns nil.
func (r *CertReloader) Run(ctx context.Context) error {
	log := zerolog.Ctx(ctx)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}
	defer watcher.Close()

	certDir := filepath.Dir(r.certPath)
	keyDir := filepath.Dir(r.keyPath)
	if err := watcher.Add(certDir); err != nil {
		return fmt.Errorf("failed to watch cert directory %s: %w", certDir, err)
	}
	if certDir != keyDir {
		if err := watcher.Add(keyDir); err != nil {
			return fmt.Errorf("failed to watch key directory %s: %w", keyDir, err)
		}
	}

	certBase := filepath.Base(r.certPath)
	keyBase := filepath.Base(r.keyPath)

	var debounceTimer *time.Timer
	var debounceC <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			base := filepath.Base(event.Name)
			if base != certBase && base != keyBase {
				continue
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}
			if debounceTimer == nil {
				log.Debug().Str("file", event.Name).Msgf(
					"detected change in %q, waiting %s for additional file changes",
					event.Name, r.debounce)
				debounceTimer = time.NewTimer(r.debounce)
				debounceC = debounceTimer.C
			} else {
				log.Debug().Str("file", event.Name).Msg("additional file change detected, resetting debounce timer")
				debounceTimer.Reset(r.debounce)
			}

		case <-debounceC:
			debounceTimer = nil
			debounceC = nil
			r.reload(log)

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Error().Err(err).Msg("file watcher error")
		}
	}
}

func (r *CertReloader) reload(log *zerolog.Logger) {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		log.Error().Err(err).Msg("failed to reload TLS certificate")
		return
	}
	r.cert.Store(&cert)
	log.Info().Msg("TLS certificate reloaded successfully")
}
