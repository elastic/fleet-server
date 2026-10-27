// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package ofrep serves the OpenFeature Remote Evaluation Protocol (OFREP) endpoints.
// See https://github.com/open-feature/protocol.
package ofrep

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog/hlog"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/definitions"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/store"
)

// Paths served by the handler.
const (
	PathBulk   = "/ofrep/v1/evaluate/flags"
	PathSingle = "/ofrep/v1/evaluate/flags/{key}"
)

// SnapshotSource returns the current definitions, or nil until they are loaded.
type SnapshotSource interface {
	Load() *store.Snapshot
}

// Observer is notified of every evaluated context. It must not block.
type Observer interface {
	Observe(app, env string, ctx eval.Context)
}

// Options configures the handler.
type Options struct {
	// AllowedOrigins lists the CORS origins allowed to call the endpoints. "*" allows any origin.
	AllowedOrigins []string
	// Observer, when set, receives the evaluated contexts.
	Observer Observer
}

type handler struct {
	src      SnapshotSource
	observer Observer
}

// NewHandler returns the OFREP HTTP handler. Routes use their full /ofrep/... paths.
func NewHandler(src SnapshotSource, opts Options) http.Handler {
	h := &handler{src: src, observer: opts.Observer}

	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(Middleware(opts.AllowedOrigins))
	r.Use(h.requireReady)
	r.Use(h.authenticate)
	r.Post(PathBulk, h.evaluateBulk)
	r.Post(PathSingle, h.evaluateSingle)
	return r
}

type evaluationRequest struct {
	Context map[string]any `json:"context"`
}

// evaluation is a successful or failed flag evaluation, as defined by OFREP.
type evaluation struct {
	Key          string `json:"key,omitempty"`
	Value        any    `json:"value,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Variant      string `json:"variant,omitempty"`
	ErrorCode    string `json:"errorCode,omitempty"`
	ErrorDetails string `json:"errorDetails,omitempty"`
}

type bulkResponse struct {
	Flags []evaluation `json:"flags"`
}

type generalError struct {
	ErrorDetails string `json:"errorDetails"`
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		hlog.FromRequest(r).Debug().Err(err).Msg("failed to write OFREP response")
	}
}

func (h *handler) requireReady(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.src.Load() == nil {
			w.Header().Set("Retry-After", "5")
			writeJSON(w, r, http.StatusServiceUnavailable, generalError{ErrorDetails: "feature flags are not loaded yet"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

type caller struct {
	app string
	env string
}

type callerKey struct{}

func token(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, value, ok := strings.Cut(auth, " ")
		if ok && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(value)
		}
		return ""
	}
	return strings.TrimSpace(r.Header.Get("X-API-Key"))
}

// lookupCredential resolves a token to a credential: SDK keys are matched by their SHA-256 hash,
// client IDs, which are public, in plain text.
func lookupCredential(snap *store.Snapshot, tok string) *definitions.Credential {
	sum := sha256.Sum256([]byte(tok))
	if c := snap.CredentialBySDKKeyHash(hex.EncodeToString(sum[:])); c != nil {
		return c
	}
	return snap.CredentialByClientID(tok)
}

func (h *handler) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := token(r)
		if tok == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, r, http.StatusUnauthorized, generalError{ErrorDetails: "missing SDK key or client ID"})
			return
		}
		cred := lookupCredential(h.src.Load(), tok)
		if cred == nil {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, r, http.StatusUnauthorized, generalError{ErrorDetails: "invalid SDK key or client ID"})
			return
		}
		ctx := r.Context()
		ctx = contextWithCaller(ctx, caller{app: cred.App, env: cred.Environment})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// readContext decodes and flattens the evaluation context of the request.
// It returns the HTTP status and error details on failure.
func readContext(r *http.Request) (eval.Context, int, string) {
	var req evaluationRequest
	dec := json.NewDecoder(r.Body)
	// Keep numbers as written, so large integer IDs keep their precision.
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		status, details := bodyStatus(err)
		return nil, status, details
	}
	// A second value, or trailing data past the body limit, must not be ignored.
	// Decode reports io.EOF only once the input is fully consumed.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		status, details := bodyStatus(err)
		return nil, status, details
	}
	ctx, err := eval.FlattenContext(req.Context)
	if err != nil {
		return nil, http.StatusBadRequest, err.Error()
	}
	return ctx, http.StatusOK, ""
}

func bodyStatus(err error) (int, string) {
	if err == nil {
		return http.StatusBadRequest, "invalid request body: trailing data"
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return http.StatusRequestEntityTooLarge, "request body too large"
	}
	return http.StatusBadRequest, "invalid request body: " + err.Error()
}

func (h *handler) observe(c caller, ctx eval.Context) {
	if h.observer != nil {
		h.observer.Observe(c.app, c.env, ctx)
	}
}

func evaluateFlag(snap *store.Snapshot, c caller, key string, ctx eval.Context) evaluation {
	flag := snap.Flag(key)
	if flag == nil || !flag.AssignedTo(c.app) || !flag.HasEnvironment(c.env) {
		return evaluation{Key: key, ErrorCode: string(eval.ErrorFlagNotFound), ErrorDetails: "flag " + key + " was not found"}
	}
	res := eval.Evaluate(flag, c.env, ctx, snap.Flag)
	if res.Failed() {
		return evaluation{Key: key, ErrorCode: string(res.ErrorCode), ErrorDetails: res.ErrorDetails}
	}
	return evaluation{Key: key, Value: res.Value, Reason: string(res.Reason), Variant: res.Variant}
}

func (h *handler) evaluateSingle(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	c := callerFromContext(r.Context())
	ctx, status, details := readContext(r)
	if status != http.StatusOK {
		writeJSON(w, r, status, evaluation{Key: key, ErrorCode: string(eval.ErrorInvalidContext), ErrorDetails: details})
		return
	}
	h.observe(c, ctx)

	res := evaluateFlag(h.src.Load(), c, key, ctx)
	switch res.ErrorCode {
	case "":
		writeJSON(w, r, http.StatusOK, res)
	case string(eval.ErrorFlagNotFound):
		writeJSON(w, r, http.StatusNotFound, res)
	default:
		writeJSON(w, r, http.StatusBadRequest, res)
	}
}

// etag identifies the bulk response: it changes with the definitions, the caller and the context.
func etag(snap *store.Snapshot, c caller, ctx eval.Context) string {
	canonical, _ := json.Marshal(ctx)
	h := sha256.New()
	for _, part := range [][]byte{[]byte(snap.Version), []byte(c.app), []byte(c.env), canonical} {
		h.Write(part)
		h.Write([]byte{0})
	}
	return `"` + hex.EncodeToString(h.Sum(nil))[:32] + `"`
}

func etagMatches(ifNoneMatch, tag string) bool {
	for candidate := range strings.SplitSeq(ifNoneMatch, ",") {
		candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
		if candidate == tag || candidate == "*" {
			return true
		}
	}
	return false
}

func (h *handler) evaluateBulk(w http.ResponseWriter, r *http.Request) {
	c := callerFromContext(r.Context())
	ctx, status, details := readContext(r)
	if status != http.StatusOK {
		writeJSON(w, r, status, evaluation{ErrorCode: string(eval.ErrorInvalidContext), ErrorDetails: details})
		return
	}
	h.observe(c, ctx)

	snap := h.src.Load()
	tag := etag(snap, c, ctx)
	w.Header().Set("ETag", tag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatches(inm, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	flags := snap.FlagsForApp(c.app)
	resp := bulkResponse{Flags: make([]evaluation, 0, len(flags))}
	for _, flag := range flags {
		if !flag.HasEnvironment(c.env) {
			continue
		}
		resp.Flags = append(resp.Flags, evaluateFlag(snap, c, flag.Key, ctx))
	}
	writeJSON(w, r, http.StatusOK, resp)
}
