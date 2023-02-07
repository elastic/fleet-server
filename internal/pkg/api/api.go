// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api

import (
	"net/http"

	"github.com/elastic/fleet-server/v7/internal/pkg/build"
	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/policy"
	"github.com/elastic/fleet-server/v7/internal/pkg/rollback"

	openapi_types "github.com/deepmap/oapi-codegen/pkg/types"
	"github.com/rs/zerolog/hlog"
)

// FIXME: Cleanup needed for: metrics endpoint (actually a separate listener?), endpoint auth
// FIXME: Should we use strict handler
type apiServer struct {
	ct     *CheckinT
	et     *EnrollerT
	at     *ArtifactT
	ack    *AckT
	st     *StatusT
	sm     policy.SelfMonitor
	bi     build.Info
	ut     *UploadT
	bulker bulk.Bulk
}

// ensure api implements the ServerInterface
var _ ServerInterface = (*apiServer)(nil)

func (a *apiServer) AgentEnroll(w http.ResponseWriter, r *http.Request, id string, params AgentEnrollParams) {
	if id != kEnrollMod {
		http.Error(w, "", http.StatusNotFound)
		return
	}
	zlog := hlog.FromRequest(r).With().Str("mod", kEnrollMod).Logger()

	// Error in the scope for deferred rolback function check
	var err error
	// Initialize rollback/cleanup for enrollment
	// This deletes all the artifacts that were created during enrollment
	rb := rollback.New(zlog)
	defer func() {
		if err != nil {
			zlog.Error().Err(err).Msg("perform rollback on enrollment failure")
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
	if err := a.ack.handleAcks(zlog, w, r, id); err != nil {
		cntAcks.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) AgentCheckin(w http.ResponseWriter, r *http.Request, id string, params AgentCheckinParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id).Logger()
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
		cntArtifacts.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadBegin(w http.ResponseWriter, r *http.Request, params UploadBeginParams) {
	zlog := hlog.FromRequest(r).With().Logger()
	err := a.ut.handleUploadBegin(zlog, w, r)
	if err != nil {
		cntUpload.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadComplete(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, params UploadCompleteParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id.String()).Logger()
	err := a.ut.handleUploadComplete(zlog, w, r, id.String())
	if err != nil {
		cntUpload.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) UploadChunk(w http.ResponseWriter, r *http.Request, id openapi_types.UUID, chunkNum int, params UploadChunkParams) {
	zlog := hlog.FromRequest(r).With().Str(LogAgentID, id.String()).Logger()

	if _, err := a.ut.authAPIKey(r, a.bulker, a.ut.cache); err != nil {
		cntUpload.IncError(err)
		ErrorResp(w, r, err)
		return
	}
	if err := a.ut.handleUploadChunk(zlog, w, r, id.String(), chunkNum, params.XChunkSHA2); err != nil {
		cntUpload.IncError(err)
		ErrorResp(w, r, err)
	}
}

func (a *apiServer) Status(w http.ResponseWriter, r *http.Request, params StatusParams) {
	zlog := hlog.FromRequest(r).With().
		Str("mod", kStatusMod).
		Logger()
	err := a.st.handleStatus(zlog, a.sm, a.bi, r, w)
	if err != nil {
		cntStatus.IncError(err)
		ErrorResp(w, r, err)
	}
}
