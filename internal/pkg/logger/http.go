// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
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
	count       uint64
	statusCode  int
	wroteHeader bool
}

func NewResponseCounter(w http.ResponseWriter) *ResponseCounter {
	return &ResponseCounter{
		ResponseWriter: w,
	}
}

func (rc *ResponseCounter) Write(buf []byte) (int, error) {
	if !rc.wroteHeader {
		rc.wroteHeader = true
		rc.statusCode = 200
	}
	n, err := rc.ResponseWriter.Write(buf)
	atomic.AddUint64(&rc.count, uint64(n))
	return n, err
}

func (rc *ResponseCounter) WriteHeader(statusCode int) {
	rc.ResponseWriter.WriteHeader(statusCode)

	// Defend unsupported multiple calls to WriteHeader
	if !rc.wroteHeader {
		rc.statusCode = statusCode
		rc.wroteHeader = true
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

	return
}

// Expects HTTP version in form of HTTP/x.y
func stripHTTP(h string) string {
	if strings.HasPrefix(h, httpSlashPrefix) {
		return h[len(httpSlashPrefix):]
	}

	return h
}

// ECS HTTP log wrapper
func HttpHandler(next httprouter.Handle) httprouter.Handle {

	return func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
		e := log.Debug()

		if !e.Enabled() {
			next(w, r, p)
			return
		}

		start := time.Now()

		rdCounter := NewReaderCounter(r.Body)
		r.Body = rdCounter

		wrCounter := NewResponseCounter(w)

		next(wrCounter, r, p)

		// Look for request id
		if reqID := r.Header.Get(HeaderRequestID); reqID != "" {
			e.Str(EcsHttpRequestId, reqID)
		}

		// URL info
		e.Str(EcsUrlFull, r.URL.String())

		if domain := r.URL.Hostname(); domain != "" {
			e.Str(EcsUrlDomain, domain)
		}

		port := r.URL.Port()
		if port != "" {
			if v, err := strconv.Atoi(port); err != nil {
				e.Int(EcsUrlPort, v)
			}
		}

		// HTTP info
		e.Str(EcsHttpVersion, stripHTTP(r.Proto))
		e.Str(EcsHttpRequestMethod, r.Method)
		e.Int(EcsHttpResponseCode, wrCounter.statusCode)
		e.Uint64(EcsHttpRequestBodyBytes, rdCounter.Count())
		e.Uint64(EcsHttpResponseBodyBytes, wrCounter.Count())

		// Client info
		remoteIP, remotePort := splitAddr(r.RemoteAddr)
		e.Str(EcsClientAddress, r.RemoteAddr)
		e.Str(EcsClientIp, remoteIP)
		e.Int(EcsClientPort, remotePort)

		// TLS info
		e.Bool(EcsTlsEstablished, (r.TLS != nil))

		// Event info
		e.Int64(EcsEventDuration, time.Since(start).Nanoseconds())

		e.Msg("HTTP handler")
	}
}
