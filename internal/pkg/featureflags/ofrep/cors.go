// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ofrep

import (
	"net/http"
	"strings"
)

const (
	corsAllowedMethods = "POST, OPTIONS"
	corsAllowedHeaders = "Authorization, Content-Type, If-None-Match, X-API-Key"
	corsExposedHeaders = "ETag"
	corsMaxAge         = "600"
)

type cors struct {
	any     bool
	origins map[string]struct{}
}

func newCORS(allowed []string) *cors {
	c := &cors{origins: make(map[string]struct{}, len(allowed))}
	for _, o := range allowed {
		o = strings.TrimRight(strings.TrimSpace(o), "/")
		if o == "*" {
			c.any = true
			continue
		}
		if o != "" {
			c.origins[o] = struct{}{}
		}
	}
	return c
}

func (c *cors) allowed(origin string) bool {
	if origin == "" {
		return false
	}
	if c.any {
		return true
	}
	_, ok := c.origins[origin]
	return ok
}

// Middleware adds CORS headers for allowed origins and answers preflight requests before next runs,
// so responses written by next (including 429) stay readable by browsers.
func Middleware(allowedOrigins []string) func(http.Handler) http.Handler {
	c := newCORS(allowedOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.handle(w, r, next)
		})
	}
}

// PrefixMiddleware is Middleware limited to paths under prefix.
// Requests outside prefix are forwarded unchanged, so it can wrap the whole server
// and still leave Fleet and OpAMP alone. Preflight is answered before next runs.
func PrefixMiddleware(prefix string, allowedOrigins []string) func(http.Handler) http.Handler {
	c := newCORS(allowedOrigins)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.URL.Path, prefix) {
				next.ServeHTTP(w, r)
				return
			}
			c.handle(w, r, next)
		})
	}
}

// handle adds CORS headers for allowed origins and answers preflight requests before
// authentication, as browsers send them without credentials.
func (c *cors) handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	origin := r.Header.Get("Origin")
	allowed := c.allowed(origin)
	if allowed {
		h := w.Header()
		// An outer wrapper may already have set these. Adding Vary again would duplicate it.
		if h.Get("Access-Control-Allow-Origin") == "" {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Expose-Headers", corsExposedHeaders)
		}
	}
	if r.Method == http.MethodOptions {
		if allowed {
			h := w.Header()
			h.Set("Access-Control-Allow-Methods", corsAllowedMethods)
			h.Set("Access-Control-Allow-Headers", corsAllowedHeaders)
			h.Set("Access-Control-Max-Age", corsMaxAge)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	next.ServeHTTP(w, r)
}
