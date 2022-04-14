// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"context"
	"net/http"

	"golang.org/x/time/rate"
)

type limitedResponseWriter struct {
	r   *rate.Limiter
	w   http.ResponseWriter
	ctx context.Context
}

// WrapResponseWriter wraps an http.ResponseWriter with a rate.Limiter that will control the Write method.
func WrapResponseWriter(ctx context.Context, w http.ResponseWriter, r *rate.Limiter) http.ResponseWriter {
	return &limitedResponseWriter{
		ctx: ctx,
		r:   r,
		w:   w,
	}
}

// Write will write to the wrapped write function with the limiter.
//
// If the limiter is not nil then operations may block until the limiter has capacity.
// If p is larger then the rate limit, writes will be batched to half the limit at a time.
func (l *limitedResponseWriter) Write(p []byte) (int, error) {
	if l.r == nil {
		return l.w.Write(p)
	}

	// If the length write is too large, write half the limit
	if len(p) > int(l.r.Limit()) {
		// TODO be smarter about pSize
		// does not handle lots of concurrency well at the moment, or existing buffers
		// i.e., the http.Transport WriteBuffer defaults to 4k
		pSize := int(l.r.Limit() / 2)
		// number of bytes, start index, end index
		n, s, e := 0, 0, pSize
		var err error
		for n < len(p) {
			err = l.r.WaitN(l.ctx, len(p[s:e]))
			if err != nil {
				return n, err
			}

			k, err := l.w.Write(p[s:e])
			n = n + k
			if err != nil {
				return n, err
			}

			s = e
			e = e + pSize
			if e > len(p) {
				e = len(p)
			}
		}
		return n, err
	}

	err := l.r.WaitN(l.ctx, len(p))
	if err != nil {
		return 0, err
	}
	return l.w.Write(p)
}

// Header calls the ResponseWriter Header function without the limiter.
func (l *limitedResponseWriter) Header() http.Header {
	return l.w.Header()
}

// WriteHeader calls the ResponseWriter WriteHeader function without the limiter.
func (l *limitedResponseWriter) WriteHeader(statusCode int) {
	l.w.WriteHeader(statusCode)
}
