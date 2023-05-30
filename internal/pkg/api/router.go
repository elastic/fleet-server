// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/limit"
	"github.com/elastic/fleet-server/v7/internal/pkg/logger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"go.elastic.co/apm/module/apmchiv5/v2"
	"go.elastic.co/apm/v2"
)

func newRouter(cfg *config.ServerLimits, si ServerInterface, tracer *apm.Tracer) http.Handler {
	r := chi.NewRouter()
	r.Use(logger.Middleware) // Attach middlewares to router directly so the occur before any request parsing/validation
	r.Use(middleware.Recoverer)
	r.Use(Limiter(cfg).middleware)
	if tracer != nil {
		r.Use(apmchiv5.Middleware(apmchiv5.WithTracer(tracer)))
	}
	return HandlerWithOptions(si, ChiServerOptions{
		BaseRouter:       r,
		ErrorHandlerFunc: ErrorResp,
		// TODO auth as middleware? - here it takes place after chi router adds scope annotations to the request ctx
	})
}

// limiter wraps routes with metrics and rate limits.
//
// auth is handled elsewhere.
type limiter struct {
	checkin        *limit.Limiter
	artifact       *limit.Limiter
	enroll         *limit.Limiter
	ack            *limit.Limiter
	status         *limit.Limiter
	uploadBegin    *limit.Limiter
	uploadChunk    *limit.Limiter
	uploadComplete *limit.Limiter
}

func Limiter(cfg *config.ServerLimits) *limiter {
	return &limiter{
		checkin:        limit.NewLimiter(&cfg.CheckinLimit),
		artifact:       limit.NewLimiter(&cfg.ArtifactLimit),
		enroll:         limit.NewLimiter(&cfg.EnrollLimit),
		ack:            limit.NewLimiter(&cfg.AckLimit),
		status:         limit.NewLimiter(&cfg.StatusLimit),
		uploadBegin:    limit.NewLimiter(&cfg.UploadStartLimit),
		uploadChunk:    limit.NewLimiter(&cfg.UploadChunkLimit),
		uploadComplete: limit.NewLimiter(&cfg.UploadEndLimit),
	}
}

// pathToOperation determines the endpoint passed on the request path.
// idealy we would be able to use chi's route context, but it is not ready this early in the stack
//
//nolint:goconst // using const values here makes it harder to read
func pathToOperation(path string) string {
	path = strings.TrimSuffix(path, "/")
	if path == "/api/status" {
		return "status"
	}
	if path == "/api/fleet/uploads" {
		return "uploadBegin"
	}
	if strings.HasPrefix(path, "/api/fleet/") {
		pp := strings.Split(strings.TrimPrefix(path, "/"), "/")
		if len(pp) == 4 {
			if pp[2] == "agents" {
				return "enroll"
			} else if pp[2] == "uploads" {
				return "uploadComplete"
			}
		} else if len(pp) == 5 {
			if pp[2] == "agents" {
				if pp[4] == "acks" || pp[4] == "checkin" {
					return pp[4]
				}
			} else if pp[2] == "uploads" {
				return "uploadChunk"
			} else if pp[2] == "artifacts" {
				return "artifact"
			}
		}
	}
	return ""
}

func (l *limiter) middleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch pathToOperation(r.URL.Path) {
		case "enroll":
			l.enroll.Wrap("enroll", &cntEnroll, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "acks":
			l.ack.Wrap("acks", &cntAcks, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "checkin":
			l.checkin.Wrap("checkin", &cntCheckin, zerolog.WarnLevel)(next).ServeHTTP(w, r)
		case "artifact":
			l.artifact.Wrap("artifact", &cntArtifacts, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "uploadBegin":
			l.uploadBegin.Wrap("uploadBegin", &cntUploadStart, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "uploadComplete":
			l.uploadComplete.Wrap("uploadComplete", &cntUploadEnd, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "uploadChunk":
			l.uploadChunk.Wrap("uploadChunk", &cntUploadChunk, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		case "status":
			l.status.Wrap("status", &cntStatus, zerolog.DebugLevel)(next).ServeHTTP(w, r)
		default:
			// no tracking or limits
			next.ServeHTTP(w, r)
		}
	}
	return http.HandlerFunc(fn)
}
