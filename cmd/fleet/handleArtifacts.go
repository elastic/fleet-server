// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/cache"
	"github.com/elastic/fleet-server/v7/internal/pkg/dl"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/throttle"

	"github.com/julienschmidt/httprouter"
	"github.com/rs/zerolog/log"
)

const (
	defaultCacheTTL    = time.Hour * 24 // TODO: configurable
	defaultMaxParallel = 8              // TODO: configurable
	defaultThrottleTTL = time.Minute    // TODO: configurable
)

var (
	artThrottle     = throttle.NewThrottle(defaultMaxParallel)
	ErrorThrottle   = errors.New("Cannot acquire throttle token")
	ErrorIdentifier = errors.New("Identifier mismatch")
	ErrorBadSha2    = errors.New("Malformed sha256")
)

func (rt Router) handleArtifacts(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var (
		id   = ps.ByName("id")
		sha2 = ps.ByName("sha2")
	)

	err := _handleArtifacts(w, r, id, sha2, rt.ct.bulker, rt.ct.cache)

	if err != nil {

		var code int
		switch err {
		case dl.ErrNotFound:
			code = http.StatusNotFound
		case ErrorThrottle:
			code = http.StatusTooManyRequests
		case context.Canceled:
			code = http.StatusServiceUnavailable
		default:
			code = http.StatusBadRequest
		}

		// TODO: return a 503 on elastic timeout, connection drop

		log.Debug().
			Err(err).
			Str("sha2", sha2).
			Str("id", id).
			Int("code", code).
			Msg("Fail artifact")

		http.Error(w, "", code)
	}
}

func _handleArtifacts(w http.ResponseWriter, r *http.Request, id, sha2 string, bulker bulk.Bulk, c cache.Cache) error {

	// Authenticate the APIKey; retrieve agent record.
	// NOTE: We are currently not using the agent record aside from logging.
	// Eventually we will use the policy id in the record to authorize access to the artifact.
	agent, err := authAgent(r, "", bulker, c)
	if err != nil {
		return err
	}

	zlog := log.With().
		Str("id", id).
		Str("sha2", sha2).
		Str("agent", agent.Id).
		Logger()

	// Input validation
	if err := validateSha2(sha2); err != nil {
		return err
	}

	// Grab artifact, whether from cache or elastic.
	artifact, err := getArtifact(r.Context(), bulker, c, sha2)
	if err != nil {
		return err
	}

	// TODO: Add per policy authorization on artifacts;
	// ie. limit the set of allowed artifacts by policy

	// Validate idenitifer in artifact record is same as url
	if artifact.Identifier != id {
		err = ErrorIdentifier
		zlog.Info().
			Err(err).
			Str("artifact_id", artifact.Identifier).
			Msg("Identifier mismatch on url")
		return err
	}

	zlog.Debug().
		Int("sz", len(artifact.Body)).
		Int64("decodedSz", artifact.DecodedSize).
		Str("compression", artifact.CompressionAlgorithm).
		Str("encryption", artifact.EncryptionAlgorithm).
		Str("created", artifact.Created).
		Msg("Artifact GET")

	// Write the payload
	if _, err = w.Write(artifact.Body); err != nil {
		zlog.Debug().Err(err).Msg("Fail HTTP write")
		return err
	}

	return nil
}

// Return artifact from cache by sha2 or fetch directly from Elastic, updating cache.
func getArtifact(ctx context.Context, bulker bulk.Bulk, c cache.Cache, sha2 string) (*model.Artifact, error) {

	// Check the cache; return immediately if found.
	if artifact, ok := c.GetArtifact(sha2); ok {
		return &artifact, nil
	}

	zlog := log.With().Str("sha2", sha2).Logger()

	// Fetch the artifact from elastic
	art, err := fetchArtifact(ctx, bulker, sha2)

	if err != nil {
		zlog.Info().Err(err).Msg("Fail retrieve artifact")
		return nil, err
	}

	// The 'Body' field type is Raw; extract to string.
	var srcPayload string
	if err = json.Unmarshal(art.Body, &srcPayload); err != nil {
		zlog.Error().Err(err).Msg("Cannot unmarshal artifact payload")
		return nil, err
	}

	// Artifact is stored base64 encoded in ElasticSearch.
	// Base64 decode the payload before putting in cache to avoid having to decode on each cache hit.
	dstPayload, err := base64.StdEncoding.DecodeString(srcPayload)
	if err != nil {
		zlog.Error().Err(err).Msg("Fail base64 decode artifact")
		return nil, err
	}

	// Reassign decoded payload before adding to cache
	art.Body = dstPayload

	// And cache it
	c.SetArtifact(sha2, *art, defaultCacheTTL)

	return art, nil
}

// Attempt to fetch the artifact down from elastic
// TODO: Design a mechanism to mitigate a DDOS attack on bogus hashes.
// Perhaps have a cache of the most recently used hashes available, and items that aren't
// in the cache can do a lookup but throttle as below.  We could update the cache every 10m or so.
func fetchArtifact(ctx context.Context, bulker bulk.Bulk, sha2 string) (*model.Artifact, error) {
	// Throttle prevents more than N outstanding requests to elastic globally and per sha2.
	if token := artThrottle.Acquire(sha2, defaultThrottleTTL); token == nil {
		return nil, ErrorThrottle
	} else {
		defer token.Release()
	}

	start := time.Now()
	artifact, err := dl.FindArtifactBySha256(ctx, bulker, sha2)

	log.Debug().
		Err(err).
		Str("sha2", sha2).
		Dur("rtt", time.Since(start)).
		Msg("fetch artifact")

	return artifact, err
}

func validateSha2(sha2 string) error {

	if len(sha2) != 64 {
		log.Info().Str("sha2", sha2).Msg("sha2 bad length")
		return ErrorBadSha2
	}

	if _, err := hex.DecodeString(sha2); err != nil {
		log.Info().Err(err).Str("sha2", sha2).Msg("sha2 is not hex")
		return ErrorBadSha2
	}

	return nil
}
