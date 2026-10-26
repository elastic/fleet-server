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

// middleware adds CORS headers for allowed origins and answers preflight requests before
// authentication, as browsers send them without credentials.
func (c *cors) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		allowed := c.allowed(origin)
		if allowed {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
			h.Set("Access-Control-Expose-Headers", corsExposedHeaders)
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
	})
}
