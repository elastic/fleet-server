// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"

	"go.elastic.co/apm/v2"

	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"

	"github.com/rs/zerolog/hlog"
)

type APIOpt func(a *apiServer)

func WithCheckin(ct *CheckinT) APIOpt {
	return func(a *apiServer) {
		a.ct = ct
	}
}

func WithEnroller(et *EnrollerT) APIOpt {
	return func(a *apiServer) {
		a.et = et
	}
}

func WithArtifact(at *ArtifactT) APIOpt {
	return func(a *apiServer) {
		a.at = at
	}
}

func WithAck(ack *AckT) APIOpt {
	return func(a *apiServer) {
		a.ack = ack
	}
}

func WithStatus(st *StatusT) APIOpt {
	return func(a *apiServer) {
		a.st = st
	}
}

func WithUpload(ut *UploadT) APIOpt {
	return func(a *apiServer) {
		a.ut = ut
	}
}

func WithFileDelivery(ft *FileDeliveryT) APIOpt {
	return func(a *apiServer) {
		a.ft = ft
	}
}

func WithPGP(pt *PGPRetrieverT) APIOpt {
	return func(a *apiServer) {
		a.pt = pt
	}
}

func WithAudit(audit *AuditT) APIOpt {
	return func(a *apiServer) {
		a.audit = audit
	}
}

func WithOpAmp(ot *OpAmpT) APIOpt {
	return func(a *apiServer) {
		a.ot = ot
	}
}

func WithTracer(tracer *apm.Tracer) APIOpt {
	return func(a *apiServer) {
		a.tracer = tracer
	}
}

// FIXME: Cleanup needed for: metrics endpoint (actually a separate listener?), endpoint auth
// FIXME: Should we use strict handler
type apiServer struct {
	ct    *CheckinT
	et    *EnrollerT
	at    *ArtifactT
	ack   *AckT
	st    *StatusT
	ut    *UploadT
	ft    *FileDeliveryT
	pt    *PGPRetrieverT
	audit *AuditT
	ot    *OpAmpT

	// tracer is used by the wrapping server to instrument the API server
	tracer *apm.Tracer
}

// ensure api implements the ServerInterface
var _ ServerInterface = (*apiServer)(nil)

func (a *apiServer) AgentEnroll(w http.ResponseWriter, r *http.Request, params AgentEnrollParams) {
	zlog := hlog.FromRequest(r).With().Str("mod", kEnrollMod).Logger()
	w.Header().Set("Content-Type", "application/json")

	// Error in the scope for deferred rolback function check
	var err error
	// Initialize rollback/cleanup for enrollment
	// This deletes all the artifacts that were created during enrollment
	rb := rollback.New(zlog)
	defer func() {
		if err != nil {
			zlog.Info().Err(err).Msg("perform rollback on enrollment failure")
			err = rb.Rollback(r.Context())
			if err != nil {
				zlog.Error().Err(err).Msg("rollback error on enrollment failure")
			}
		}
	}()

	err = a.et.handleEnroll(zlog, w, r, rb, params.UserAgent)

	if err != nil {
		cntEnroll.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) AgentAcks(w http.ResponseWriter, r *http.Request, id string, params AgentAcksParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
	w.Header().Set("Content-Type", "application/json")
	if err := a.ack.handleAcks(zlog, w, r, id); err != nil {
		cntAcks.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) AgentCheckin(w http.ResponseWriter, r *http.Request, id string, params AgentCheckinParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
	w.Header().Set("Content-Type", "application/json")
	err := a.ct.handleCheckin(zlog, w, r, id, params.UserAgent)
	if err != nil {
		cntCheckin.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) Artifact(w http.ResponseWriter, r *http.Request, id string, sha2 string, params ArtifactParams) {
	zlog := hlog.FromRequest(r).With().
		Str(LogAgentID, id).
		Str("sha2", sha2).
		Str("remoteAddr", r.RemoteAddr).
		Logger()

	err := a.at.handleArtifacts(zlog, w, r, id, sha2)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		cntArtifacts.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadBegin(w http.ResponseWriter, r *http.Request, params UploadBeginParams) {
	zlog := hlog.FromRequest(r).With().Logger()
	w.Header().Set("Content-Type", "application/json")
	err := a.ut.handleUploadBegin(zlog, w, r)
	if err != nil {
		cntUploadStart.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadComplete(w http.ResponseWriter, r *http.Request, id string, params UploadCompleteParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
	w.Header().Set("Content-Type", "application/json")
	err := a.ut.handleUploadComplete(zlog, w, r, id)
	if err != nil {
		cntUploadEnd.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadChunk(w http.ResponseWriter, r *http.Request, id string, chunkNum int, params UploadChunkParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
	w.Header().Set("Content-Type", "application/json")

	if _, err := a.ut.authAPIKey(r, a.ut.bulker, a.ut.cache); err != nil {
		cntUploadChunk.IncError(err)
		ErrorResp(w, r, err)
		return
	}
	if err := a.ut.handleUploadChunk(zlog, w, r, id, chunkNum, params.XChunkSHA2); err != nil {
		cntUploadChunk.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) GetFile(w http.ResponseWriter, r *http.Request, id string, params GetFileParams) {
	zlog := hlog.FromRequest(r).With().Logger()
	if err := a.ft.handleSendFile(zlog, w, r, id); err != nil {
		cntFileDeliv.IncError(err)
		w.Header().Set("Content-Type", "application/json")
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) GetPGPKey(w http.ResponseWriter, r *http.Request, major, minor, patch int, params GetPGPKeyParams) {
	zlog := hlog.FromRequest(r).With().Logger()
	if err := a.pt.handlePGPKey(zlog, w, r, major, minor, patch); err != nil {
		cntGetPGP.IncError(err)
		w.Header().Set("Content-Type", "application/json")
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) AuditUnenroll(w http.ResponseWriter, r *http.Request, id string, params AuditUnenrollParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
	if err := a.audit.handleUnenroll(zlog, w, r, id); err != nil {
		w.Header().Set("Content-Type", "application/json")
		cntAuditUnenroll.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) Status(w http.ResponseWriter, r *http.Request, params StatusParams) {
	zlog := hlog.FromRequest(r).With().
		Str("mod", kStatusMod).
		Logger()
	w.Header().Set("Content-Type", "application/json")
	err := a.st.handleStatus(zlog, r, w)
	if err != nil {
		cntStatus.IncError(err)
		ErrorResp(w, r, err)
	}
}
