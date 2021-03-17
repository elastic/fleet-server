// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultMaxParallel = 8              // TODO: configurable
	defaultCacheTTL    = time.Hour * 24 // TODO: configurable
	defaultThrottleTTL = time.Minute    // TODO: configurable
)

var (
	artThrottle       = throttle.NewThrottle(defaultMaxParallel)
	ErrorThrottle     = errors.New("cannot acquire throttle token")
	ErrorBadSha2      = errors.New("malformed sha256")
	ErrorRecord       = errors.New("artifact record mismatch")
	ErrorMismatchSha2 = errors.New("mismatched sha256")
)

func (rt Router) handleArtifacts(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()

	var (
		id   = ps.ByName("id")   // Identifier in the artifact record
		sha2 = ps.ByName("sha2") // EncodedSha256 in the artifact record
	)

	zlog := log.With().
		Str("id", id).
		Str("sha2", sha2).
		Str("remoteAddr", r.RemoteAddr).
		Logger()

	// Authenticate the APIKey; retrieve agent record.
	agent, err := authAgent(r, "", rt.ct.bulker, rt.ct.cache)
	if err != nil {
		code := http.StatusUnauthorized
		zlog.Info().
			Err(err).
			Int("code", code).
			Msg("Fail auth")

		http.Error(w, "", code)
		return
	}

	if agent.Agent != nil {
		zlog = zlog.With().Str("agentId", agent.Agent.Id).Logger()
	}

	ah := artHandler{
		zlog:   zlog,
		bulker: rt.ct.bulker,
		c:      rt.ct.cache,
	}

	rdr, err := ah.handle(r.Context(), agent, id, sha2)

	var nWritten int64
	if err == nil {
		nWritten, err = io.Copy(w, rdr)
		zlog.Trace().
			Err(err).
			Int64("nWritten", nWritten).
			Dur("rtt", time.Since(start)).
			Msg("Response sent")
	}

	if err != nil {
		code, lvl := assessError(err)

		zlog.WithLevel(lvl).
			Err(err).
			Int("code", code).
			Int64("nWritten", nWritten).
			Dur("rtt", time.Since(start)).
			Msg("Fail handle artifact")

		http.Error(w, "", code)
	}
}

func assessError(err error) (int, zerolog.Level) {
	lvl := zerolog.DebugLevel

	// TODO: return a 503 on elastic timeout, connection drop

	var code int
	switch err {
	case dl.ErrNotFound:
		// Artifact not found indicates a race condition upstream
		// or an attack on the fleet server.  Either way it should
		// show up in the logs at a higher level than debug
		lvl = zerolog.WarnLevel
		code = http.StatusNotFound
	case ErrorThrottle:
		code = http.StatusTooManyRequests
	case context.Canceled:
		code = http.StatusServiceUnavailable
	default:
		code = http.StatusBadRequest
	}

	return code, lvl
}

type artHandler struct {
	zlog   zerolog.Logger
	bulker bulk.Bulk
	c      cache.Cache
}

func (ah artHandler) handle(ctx context.Context, agent *model.Agent, id, sha2 string) (io.Reader, error) {

	// Input validation
	if err := validateSha2String(sha2); err != nil {
		return nil, err
	}

	// Determine whether the agent should have access to this artifact
	if err := ah.authorizeArtifact(ctx, agent, id, sha2); err != nil {
		ah.zlog.Warn().Err(err).Msg("Unauthorized GET on artifact")
		return nil, err
	}

	// Grab artifact, whether from cache or elastic.
	artifact, err := ah.getArtifact(ctx, id, sha2)
	if err != nil {
		return nil, err
	}

	// Sanity check; just in case something underneath is misbehaving
	if artifact.Identifier != id || artifact.EncodedSha256 != sha2 {
		err = ErrorRecord
		ah.zlog.Info().
			Err(err).
			Str("artifact_id", artifact.Identifier).
			Str("artifact_sha2", artifact.EncodedSha256).
			Msg("Identifier mismatch on url")
		return nil, err
	}

	ah.zlog.Debug().
		Int("sz", len(artifact.Body)).
		Int64("decodedSz", artifact.DecodedSize).
		Str("compression", artifact.CompressionAlgorithm).
		Str("encryption", artifact.EncryptionAlgorithm).
		Str("created", artifact.Created).
		Msg("Artifact GET")

	// Write the payload
	rdr := bytes.NewReader(artifact.Body)
	return rdr, nil
}

// TODO: Pull the policy record for this agent and validate that the
// requested artifact is assigned to this policy.  This will prevent
// agents from retrieving artifacts that they do not have access to.
// Note that this is racy, the policy could have changed to allow an
// artifact before this instantiation of FleetServer has its local
// copy updated.  Take the race conditions into consideration.
//
// Initial implementation is dependent on security by obscurity; ie.
// it should be difficult for an attacker to guess a guid.
func (ah artHandler) authorizeArtifact(ctx context.Context, agent *model.Agent, ident, sha2 string) error {
	return nil // TODO
}

// Return artifact from cache by sha2 or fetch directly from Elastic.
// Update cache on successful retrieval from Elastic.
func (ah artHandler) getArtifact(ctx context.Context, ident, sha2 string) (*model.Artifact, error) {

	// Check the cache; return immediately if found.
	if artifact, ok := ah.c.GetArtifact(ident, sha2); ok {
		return &artifact, nil
	}

	// Fetch the artifact from elastic
	art, err := ah.fetchArtifact(ctx, ident, sha2)

	if err != nil {
		ah.zlog.Info().Err(err).Msg("Fail retrieve artifact")
		return nil, err
	}

	// The 'Body' field type is Raw; extract to string.
	var srcPayload string
	if err = json.Unmarshal(art.Body, &srcPayload); err != nil {
		ah.zlog.Error().Err(err).Msg("Cannot unmarshal artifact payload")
		return nil, err
	}

	// Artifact is stored base64 encoded in ElasticSearch.
	// Base64 decode the payload before putting in cache
	// to avoid having to decode on each cache hit.
	dstPayload, err := base64.StdEncoding.DecodeString(srcPayload)
	if err != nil {
		ah.zlog.Error().Err(err).Msg("Fail base64 decode artifact")
		return nil, err
	}

	// Validate the sha256 hash; this is just good hygiene.
	if err = validateSha2Data(dstPayload, art.EncodedSha256); err != nil {
		ah.zlog.Error().Err(err).Msg("Fail sha2 hash validation")
		return nil, err
	}

	// Reassign decoded payload before adding to cache, avoid base64 decode on cache hit.
	art.Body = dstPayload

	// Update the cache.
	ah.c.SetArtifact(*art, defaultCacheTTL)

	return art, nil
}

// Attempt to fetch the artifact from Elastic
// TODO: Design a mechanism to mitigate a DDOS attack on bogus hashes.
// Perhaps have a cache of the most recently used hashes available, and items that aren't
// in the cache can do a lookup but throttle as below.  We could update the cache every 10m or so.
func (ah artHandler) fetchArtifact(ctx context.Context, ident, sha2 string) (*model.Artifact, error) {
	// Throttle prevents more than N outstanding requests to elastic globally and per sha2.
	if token := artThrottle.Acquire(sha2, defaultThrottleTTL); token == nil {
		return nil, ErrorThrottle
	} else {
		defer token.Release()
	}

	start := time.Now()
	artifact, err := dl.FindArtifact(ctx, ah.bulker, ident, sha2)

	ah.zlog.Info().
		Err(err).
		Dur("rtt", time.Since(start)).
		Msg("fetch artifact")

	return artifact, err
}

func validateSha2String(sha2 string) error {

	if len(sha2) != 64 {
		return ErrorBadSha2
	}

	if _, err := hex.DecodeString(sha2); err != nil {
		return ErrorBadSha2
	}

	return nil
}

func validateSha2Data(data []byte, sha2 string) error {
	src, err := hex.DecodeString(sha2)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	if !bytes.Equal(sum[:], src) {
		return ErrorMismatchSha2
	}

	return nil
}
