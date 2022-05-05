// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/elastic/fleet-server/v7/internal/pkg/apikey"
)

const (
	HeaderRequestID = "X-Request-ID"
	httpSlashPrefix = "HTTP/"
)

type ReaderCounter struct {
	io.ReadCloser
	count uint64
}

func NewReaderCounter(r io.ReadCloser) *ReaderCounter {
	return &ReaderCounter{
		ReadCloser: r,
	}
}

func (rd *ReaderCounter) Read(buf []byte) (int, error) {
	n, err := rd.ReadCloser.Read(buf)
	atomic.AddUint64(&rd.count, uint64(n))
	return n, err
}

func (rd *ReaderCounter) Count() uint64 {
	return atomic.LoadUint64(&rd.count)
}

type ResponseCounter struct {
	http.ResponseWriter
	count      uint64
	statusCode int
}

func NewResponseCounter(w http.ResponseWriter) *ResponseCounter {
	return &ResponseCounter{
		ResponseWriter: w,
	}
}

func (rc *ResponseCounter) Write(buf []byte) (int, error) {
	if rc.statusCode == 0 {
		rc.WriteHeader(http.StatusOK)
	}

	n, err := rc.ResponseWriter.Write(buf)
	atomic.AddUint64(&rc.count, uint64(n))
	return n, err
}

func (rc *ResponseCounter) WriteHeader(statusCode int) {
	rc.ResponseWriter.WriteHeader(statusCode)

	// Defend unsupported multiple calls to WriteHeader
	if rc.statusCode == 0 {
		rc.statusCode = statusCode
	}
}

func (rc *ResponseCounter) Count() uint64 {
	return atomic.LoadUint64(&rc.count)
}

func splitAddr(addr string) (host string, port int) {
	host, portS, err := net.SplitHostPort(addr)
	if err == nil {
		if v, err := strconv.Atoi(portS); err == nil {
			port = v
		}
	}

	return //nolint:nakedret // short function
}

// Expects HTTP version in form of HTTP/x.y
func stripHTTP(h string) string {

	switch h {
	case "HTTP/2.0":
		return "2.0"
	case "HTTP/1.1":
		return "1.1" //nolint:goconst // 1.1 is used by http and tls
	default:
		if strings.HasPrefix(h, httpSlashPrefix) {
			return h[len(httpSlashPrefix):]
		}
	}

	return h
}

func httpMeta(r *http.Request, e *zerolog.Event) {
	// Look for request id
	if reqID := r.Header.Get(HeaderRequestID); reqID != "" {
		e.Str(ECSHTTPRequestID, reqID)
	}

	oldForce := r.URL.ForceQuery
	r.URL.ForceQuery = false
	e.Str(ECSURLFull, r.URL.String())
	r.URL.ForceQuery = oldForce

	if domain := r.URL.Hostname(); domain != "" {
		e.Str(ECSURLDomain, domain)
	}

	port := r.URL.Port()
	if port != "" {
		if v, err := strconv.Atoi(port); err == nil {
			e.Int(ECSURLPort, v)
		}
	}

	// HTTP info
	e.Str(ECSHTTPVersion, stripHTTP(r.Proto))
	e.Str(ECSHTTPRequestMethod, r.Method)

	// ApiKey
	if apiKey, err := apikey.ExtractAPIKey(r); err == nil {
		e.Str(APIKeyID, apiKey.ID)
	}

	// Client info
	if r.RemoteAddr != "" {
		e.Str(ECSClientAddress, r.RemoteAddr)
	}

	// TLS info
	e.Bool(ECSTLSEstablished, r.TLS != nil)
}

func httpDebug(r *http.Request, e *zerolog.Event) {
	// Client info
	if r.RemoteAddr != "" {
		remoteIP, remotePort := splitAddr(r.RemoteAddr)
		e.Str(ECSClientIP, remoteIP)
		e.Int(ECSClientPort, remotePort)
	}

	if r.TLS != nil {

		e.Str(ECSTLSVersion, TLSVersionToString(r.TLS.Version))
		e.Str(ECSTLSCipher, tls.CipherSuiteName(r.TLS.CipherSuite))
		e.Bool(ECSTLSsResumed, r.TLS.DidResume)

		if r.TLS.ServerName != "" {
			e.Str(ECSTLSClientServerName, r.TLS.ServerName)
		}

		if len(r.TLS.PeerCertificates) > 0 && r.TLS.PeerCertificates[0] != nil {
			leaf := r.TLS.PeerCertificates[0]
			if leaf.SerialNumber != nil {
				e.Str(ECSTLSClientSerialNumber, leaf.SerialNumber.String())
			}
			e.Str(ECSTLSClientIssuer, leaf.Issuer.String())
			e.Str(ECSTLSClientSubject, leaf.Subject.String())
			e.Str(ECSTLSClientNotBefore, leaf.NotBefore.UTC().Format(ECSTLSClientTimeFormat))
			e.Str(ECSTLSClientNotAfter, leaf.NotAfter.UTC().Format(ECSTLSClientTimeFormat))
		}
	}
}

// HTTPHandler returns an httprouter.Handle that wraps the request with an ECS logger and
// captures metrics for the current request.
func HTTPHandler(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		e := log.Info()

		if !e.Enabled() {
			next(w, r, p)
			return
		}

		start := time.Now()

		rdCounter := NewReaderCounter(r.Body)
		r.Body = rdCounter

		wrCounter := NewResponseCounter(w)

		if log.Debug().Enabled() {
			d := log.Debug()
			httpMeta(r, d)
			httpDebug(r, d)
			d.Msg("HTTP start")
		}

		next(wrCounter, r, p)

		httpMeta(r, e)

		// Only logs non 2xx errors unless we are debugging.
		if log.Debug().Enabled() || (wrCounter.statusCode < 200 && wrCounter.statusCode >= 300) {
			e.Uint64(ECSHTTPRequestBodyBytes, rdCounter.Count())
			e.Uint64(ECSHTTPResponseBodyBytes, wrCounter.Count())
			e.Int(ECSHTTPResponseCode, wrCounter.statusCode)
			e.Int64(ECSEventDuration, time.Since(start).Nanoseconds())

			e.Msgf("%d HTTP Request", wrCounter.statusCode)
		}
	}
}

func TLSVersionToString(vers uint16) string {
	switch vers {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	default:
	}

	return fmt.Sprintf("unknown_0x%x", vers)
}
