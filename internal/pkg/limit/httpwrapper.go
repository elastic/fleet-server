// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limit

import (
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// HTTPWrapper enforces rate limits for each API endpoint.
type HTTPWrapper struct {
	checkin     *limiter
	artifact    *limiter
	enroll      *limiter
	ack         *limiter
	status      *limiter
	uploadStart *limiter
	uploadEnd   *limiter
	uploadChunk *limiter
	log         zerolog.Logger
}

// Create a new HTTPWrapper using the specified limits.
func NewHTTPWrapper(addr string, cfg *config.ServerLimits) *HTTPWrapper {
	return &HTTPWrapper{
		checkin:     newLimiter(&cfg.CheckinLimit),
		artifact:    newLimiter(&cfg.ArtifactLimit),
		enroll:      newLimiter(&cfg.EnrollLimit),
		ack:         newLimiter(&cfg.AckLimit),
		status:      newLimiter(&cfg.StatusLimit),
		uploadStart: newLimiter(&cfg.UploadStartLimit),
		uploadEnd:   newLimiter(&cfg.UploadEndLimit),
		uploadChunk: newLimiter(&cfg.UploadChunkLimit),
		log:         log.With().Str("addr", addr).Logger(),
	}
}

// WhapCheckin wraps the checkin handler with the rate limiter and tracks statistics for the endpoint.
func (l *HTTPWrapper) WrapCheckin(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.checkin.wrap(l.log.With().Str("route", "checkin").Logger(), zerolog.WarnLevel, h, i)
}

// WhapArtifact wraps the artifact handler with the rate limiter and tracks statistics for the endpoint.
func (l *HTTPWrapper) WrapArtifact(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.artifact.wrap(l.log.With().Str("route", "artifact").Logger(), zerolog.DebugLevel, h, i)
}

// WhapEnroll wraps the enroll handler with the rate limiter and tracks statistics for the endpoint.
func (l *HTTPWrapper) WrapEnroll(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.enroll.wrap(l.log.With().Str("route", "enroll").Logger(), zerolog.DebugLevel, h, i)
}

// WhapAck wraps the ack handler with the rate limiter and tracks statistics for the endpoint.
func (l *HTTPWrapper) WrapAck(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.ack.wrap(l.log.With().Str("route", "ack").Logger(), zerolog.DebugLevel, h, i)
}

// WhapStatus wraps the checkin handler with the rate limiter and tracks statistics for the endpoint.
func (l *HTTPWrapper) WrapStatus(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.status.wrap(l.log.With().Str("route", "status").Logger(), zerolog.DebugLevel, h, i)
}

func (l *HTTPWrapper) WrapUploadStart(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.uploadStart.wrap(l.log.With().Str("route", "uploadStart").Logger(), zerolog.DebugLevel, h, i)
}

func (l *HTTPWrapper) WrapUploadEnd(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.uploadEnd.wrap(l.log.With().Str("route", "uploadEnd").Logger(), zerolog.DebugLevel, h, i)
}

func (l *HTTPWrapper) WrapUploadChunk(h httprouter.Handle, i StatIncer) httprouter.Handle {
	return l.uploadChunk.wrap(l.log.With().Str("route", "uploadChunk").Logger(), zerolog.DebugLevel, h, i)
}

// StatIncer is the interface used to count statistics associated with an endpoint.
type StatIncer interface {
	IncError(error)
	IncStart() func()
}
