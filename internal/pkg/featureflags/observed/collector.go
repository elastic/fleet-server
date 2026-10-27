// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package observed collects the evaluation contexts seen by the OFREP endpoints and writes them
// to the observed contexts index, one document per app, environment and context key.
// Kibana uses them to suggest attributes and values in its rule editor.
package observed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/rs/zerolog"

	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/esclient"
	"github.com/elastic/fleet-server/v7/internal/pkg/featureflags/eval"
)

const (
	// MaxValueLength is the maximum number of characters stored per attribute value.
	MaxValueLength = 256

	defaultBufferSize = 4096
	defaultMaxPending = 50_000
	defaultMaxKnown   = 100_000
)

// Attribute types recorded in attribute_types.
const (
	TypeString  = "string"
	TypeNumber  = "number"
	TypeBoolean = "boolean"
)

// updateScript replaces the mutable fields of a known context when the incoming observation is
// newer. A partial "doc" update can't be used: it would merge the old and new context objects
// instead of replacing them. last_seen is compared as epoch millis; RFC3339Nano strings do not
// order lexicographically (".10Z" is less than ".9Z").
const updateScript = "if (ctx._source.last_seen == null || " +
	"ZonedDateTime.parse(ctx._source.last_seen.toString()).toInstant().toEpochMilli() < params.last_seen_ms) { " +
	"ctx._source.context = params.context; " +
	"ctx._source.attributes = params.attributes; " +
	"ctx._source.attribute_types = params.attribute_types; " +
	"ctx._source.last_seen = params.last_seen; " +
	"}"

// Options configures the Collector.
type Options struct {
	Index                  string
	FlushInterval          time.Duration
	MaxNewContextsPerFlush int
	LastSeenResolution     time.Duration
	ExcludeAttributes      []string

	// BufferSize bounds the observations waiting to be processed. Defaults to 4096.
	BufferSize int
	// MaxPending bounds the distinct contexts kept between flushes. Defaults to 50000.
	MaxPending int
	// MaxKnown bounds the contexts remembered as written. Defaults to 100000.
	MaxKnown int
}

type observation struct {
	app, env string
	ctx      eval.Context
	at       time.Time
}

type entry struct {
	App            string            `json:"app"`
	Environment    string            `json:"environment"`
	ContextKey     string            `json:"context_key"`
	Context        map[string]any    `json:"context"`
	Attributes     []string          `json:"attributes"`
	AttributeTypes map[string]string `json:"attribute_types"`
	FirstSeen      string            `json:"first_seen,omitempty"`
	LastSeen       string            `json:"last_seen"`

	lastSeen time.Time
}

// Collector buffers observed contexts and periodically upserts them.
// Observe never blocks: when the buffers are full, observations are dropped.
type Collector struct {
	client  esclient.Client
	opts    Options
	exclude map[string]struct{}
	log     zerolog.Logger
	now     func() time.Time

	in      chan observation
	dropped atomic.Uint64

	// Only accessed by the Run goroutine.
	pending map[string]*entry
	known   map[string]time.Time
}

// New returns a Collector writing to opts.Index.
func New(client esclient.Client, opts Options, log zerolog.Logger) *Collector {
	if opts.BufferSize <= 0 {
		opts.BufferSize = defaultBufferSize
	}
	if opts.MaxPending <= 0 {
		opts.MaxPending = defaultMaxPending
	}
	if opts.MaxKnown <= 0 {
		opts.MaxKnown = defaultMaxKnown
	}
	exclude := make(map[string]struct{}, len(opts.ExcludeAttributes))
	for _, a := range opts.ExcludeAttributes {
		exclude[a] = struct{}{}
	}
	return &Collector{
		client:  client,
		opts:    opts,
		exclude: exclude,
		log:     log,
		now:     time.Now,
		in:      make(chan observation, opts.BufferSize),
		pending: map[string]*entry{},
		known:   map[string]time.Time{},
	}
}

// Observe records that ctx was evaluated for app and env. ctx must not be modified afterwards.
func (c *Collector) Observe(app, env string, ctx eval.Context) {
	select {
	case c.in <- observation{app: app, env: env, ctx: ctx, at: c.now()}:
	default:
		c.dropped.Add(1)
	}
}

// Run processes observations and flushes them every flush interval until ctx is done.
func (c *Collector) Run(ctx context.Context) error {
	t := time.NewTicker(c.opts.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case o := <-c.in:
			c.add(o)
		case <-t.C:
			c.flush(ctx)
		}
	}
}

// DocID returns the observed contexts document ID of a context.
func DocID(app, env, contextKey string) string {
	sum := sha256.Sum256([]byte(app + "|" + env + "|" + contextKey))
	return hex.EncodeToString(sum[:])
}

func (c *Collector) add(o observation) {
	e := c.toEntry(o)
	id := DocID(e.App, e.Environment, e.ContextKey)
	if _, ok := c.pending[id]; !ok && len(c.pending) >= c.opts.MaxPending {
		c.dropped.Add(1)
		return
	}
	c.pending[id] = e
}

func truncate(s string) string {
	if utf8.RuneCountInString(s) <= MaxValueLength {
		return s
	}
	runes := []rune(s)
	return string(runes[:MaxValueLength])
}

func (c *Collector) toEntry(o observation) *entry {
	e := &entry{
		App:            o.app,
		Environment:    o.env,
		Context:        make(map[string]any, len(o.ctx)),
		AttributeTypes: make(map[string]string, len(o.ctx)),
		lastSeen:       o.at,
	}
	// Identity is taken from the original values. Stored attribute values are truncated afterwards,
	// so two targeting keys that share a 256-character prefix stay distinct documents.
	identity := make(map[string]any, len(o.ctx))
	var contextKey string
	if tk, ok := o.ctx[eval.TargetingKey].(string); ok && tk != "" {
		if _, skip := c.exclude[eval.TargetingKey]; !skip {
			contextKey = tk
		}
	}
	for k, v := range o.ctx {
		if _, skip := c.exclude[k]; skip {
			continue
		}
		switch t := v.(type) {
		case string:
			identity[k] = t
			e.Context[k] = truncate(t)
			e.AttributeTypes[k] = TypeString
		case bool:
			identity[k] = t
			e.Context[k] = t
			e.AttributeTypes[k] = TypeBoolean
		case float64, json.Number:
			identity[k] = t
			e.Context[k] = t
			e.AttributeTypes[k] = TypeNumber
		default:
			// Lists are stored in their JSON form.
			b, err := json.Marshal(t)
			if err != nil {
				continue
			}
			identity[k] = string(b)
			e.Context[k] = truncate(string(b))
			e.AttributeTypes[k] = TypeString
		}
		e.Attributes = append(e.Attributes, k)
	}
	slices.Sort(e.Attributes)
	if e.Attributes == nil {
		e.Attributes = []string{}
	}

	if contextKey != "" {
		e.ContextKey = contextKey
	} else {
		// encoding/json sorts map keys, so this is a canonical form of the untruncated context.
		canonical, _ := json.Marshal(identity)
		sum := sha256.Sum256(canonical)
		e.ContextKey = hex.EncodeToString(sum[:])
	}
	return e
}

type bulkResponse struct {
	Errors bool `json:"errors"`
	Items  []map[string]struct {
		ID     string `json:"_id"`
		Status int    `json:"status"`
		Error  *struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		} `json:"error"`
	} `json:"items"`
}

func (c *Collector) indexExists(ctx context.Context) (bool, error) {
	_, err := c.client.Search(ctx, c.opts.Index, []byte(`{"size":0,"track_total_hits":false}`))
	if errors.Is(err, esclient.ErrIndexNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (c *Collector) flush(ctx context.Context) {
	if dropped := c.dropped.Swap(0); dropped > 0 {
		c.log.Debug().Uint64("dropped", dropped).Msg("observed contexts dropped because the buffers were full")
	}
	if len(c.pending) == 0 {
		return
	}
	entries := c.pending
	c.pending = make(map[string]*entry, len(entries))

	// Fleet Server never creates the index: an upsert would create it with dynamic mappings.
	exists, err := c.indexExists(ctx)
	if err != nil {
		c.log.Warn().Err(err).Msg("failed to check the observed contexts index, skipping flush")
		return
	}
	if !exists {
		c.log.Debug().Str("index", c.opts.Index).Msg("observed contexts index does not exist, skipping flush")
		return
	}

	var buf bytes.Buffer
	written := make(map[string]time.Time, len(entries))
	newPerScope := map[string]int{}
	sampledOut := 0
	for id, e := range entries {
		e.LastSeen = e.lastSeen.UTC().Format(time.RFC3339Nano)
		params := map[string]any{
			"context":         e.Context,
			"attributes":      e.Attributes,
			"attribute_types": e.AttributeTypes,
			"last_seen":       e.LastSeen,
			"last_seen_ms":    e.lastSeen.UnixMilli(),
		}
		body := map[string]any{"script": map[string]any{"lang": "painless", "source": updateScript, "params": params}}

		if last, ok := c.known[id]; ok {
			if e.lastSeen.Sub(last) <= c.opts.LastSeenResolution {
				continue
			}
		} else {
			scope := e.App + "|" + e.Environment
			if newPerScope[scope] >= c.opts.MaxNewContextsPerFlush {
				sampledOut++
				continue
			}
			newPerScope[scope]++
			e.FirstSeen = e.LastSeen
			body["upsert"] = e
		}
		if err := writeBulkUpdate(&buf, c.opts.Index, id, body); err != nil {
			c.log.Warn().Err(err).Msg("failed to encode observed context")
			continue
		}
		written[id] = e.lastSeen
	}
	if sampledOut > 0 {
		c.log.Debug().Int("sampled_out", sampledOut).Msg("new observed contexts over the per-flush limit were dropped")
	}
	if len(written) == 0 {
		return
	}

	data, err := c.client.Bulk(ctx, buf.Bytes())
	if err != nil {
		c.log.Warn().Err(err).Int("contexts", len(written)).Msg("failed to write observed contexts")
		return
	}
	var resp bulkResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		c.log.Warn().Err(err).Msg("failed to decode observed contexts bulk response")
		return
	}
	failed := 0
	for _, item := range resp.Items {
		for _, res := range item {
			if res.Error == nil {
				if at, ok := written[res.ID]; ok {
					c.known[res.ID] = at
				}
				continue
			}
			// The document was removed (e.g. by retention): write it as new next time.
			delete(c.known, res.ID)
			failed++
			if res.Error.Type != "document_missing_exception" {
				c.log.Debug().Str("type", res.Error.Type).Str("reason", res.Error.Reason).Msg("observed context write failed")
			}
		}
	}
	c.trimKnown()
	c.log.Debug().Int("written", len(written)-failed).Int("failed", failed).Msg("observed contexts flushed")
}

func (c *Collector) trimKnown() {
	if len(c.known) <= c.opts.MaxKnown {
		return
	}
	// Forgetting a context only costs an extra write the next time it is observed.
	excess := len(c.known) - c.opts.MaxKnown/2
	for id := range c.known {
		if excess == 0 {
			break
		}
		delete(c.known, id)
		excess--
	}
}

func writeBulkUpdate(buf *bytes.Buffer, index, id string, body map[string]any) error {
	meta, err := json.Marshal(map[string]any{
		"update": map[string]any{"_index": index, "_id": id, "retry_on_conflict": 3},
	})
	if err != nil {
		return err
	}
	src, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encoding %s: %w", id, err)
	}
	buf.Write(meta)
	buf.WriteByte('\n')
	buf.Write(src)
	buf.WriteByte('\n')
	return nil
}
