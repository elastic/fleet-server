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
	// Ordinary contexts stay under the count cap. A burst of large targeting keys does not.
	defaultMaxPendingBytes = 64 << 20
	// Elasticsearch rejects a bulk body above http.max_content_length, which defaults to 100 MiB.
	defaultMaxBulkBytes = 8 << 20
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
	// MaxPendingBytes bounds the bytes retained by queued and pending observations.
	// The full targeting key is counted, not only the truncated stored value. Defaults to 64 MiB.
	MaxPendingBytes int
	// MaxBulkBytes bounds each bulk request. A larger flush is sent as several requests. Defaults to 8 MiB.
	MaxBulkBytes int
}

type observation struct {
	app, env string
	ctx      eval.Context
	at       time.Time
	// bytes is the memory already charged to the collector for this observation.
	bytes int
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
	size     int
}

// Collector buffers observed contexts and periodically upserts them.
// Observe never blocks: when the buffers are full, observations are dropped.
type Collector struct {
	client  esclient.Client
	opts    Options
	exclude map[string]struct{}
	log     zerolog.Logger
	now     func() time.Time

	in       chan observation
	dropped  atomic.Uint64
	retained atomic.Int64

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
	if opts.MaxPendingBytes <= 0 {
		opts.MaxPendingBytes = defaultMaxPendingBytes
	}
	if opts.MaxBulkBytes <= 0 {
		opts.MaxBulkBytes = defaultMaxBulkBytes
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
	size := contextBytes(ctx)
	if !c.reserve(size) {
		c.dropped.Add(1)
		return
	}
	select {
	case c.in <- observation{app: app, env: env, ctx: ctx, at: c.now(), bytes: size}:
	default:
		c.release(size)
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
	if o.bytes == 0 {
		o.bytes = contextBytes(o.ctx)
		if !c.reserve(o.bytes) {
			c.dropped.Add(1)
			return
		}
	}
	// A context written within last_seen_resolution is remembered by document id only.
	// Its body is not queued: the next flush would skip it, and the entry would occupy a pending slot.
	// The remembered time stays at the last write, so a poll after the resolution is stored.
	if last, ok := c.known[DocID(o.app, o.env, c.contextKey(o.ctx))]; ok && o.at.Sub(last) <= c.opts.LastSeenResolution {
		c.release(o.bytes)
		return
	}
	e := c.toEntry(o)
	e.size = entryBytes(e)
	id := DocID(e.App, e.Environment, e.ContextKey)
	if prev, ok := c.pending[id]; ok {
		delta := e.size - prev.size - o.bytes
		if delta > 0 && !c.reserve(delta) {
			c.release(o.bytes)
			c.dropped.Add(1)
			return
		}
		if delta < 0 {
			c.release(-delta)
		}
		c.pending[id] = e
		return
	}
	if len(c.pending) >= c.opts.MaxPending || (e.size > o.bytes && !c.reserve(e.size-o.bytes)) {
		c.release(o.bytes)
		c.dropped.Add(1)
		return
	}
	if e.size < o.bytes {
		c.release(o.bytes - e.size)
	}
	c.pending[id] = e
}

func (c *Collector) reserve(n int) bool {
	if n < 0 {
		n = 0
	}
	limit := int64(c.opts.MaxPendingBytes)
	for {
		cur := c.retained.Load()
		next := cur + int64(n)
		if next > limit {
			return false
		}
		if c.retained.CompareAndSwap(cur, next) {
			return true
		}
	}
}

func (c *Collector) release(n int) {
	if n <= 0 {
		return
	}
	for {
		cur := c.retained.Load()
		next := max(cur-int64(n), 0)
		if c.retained.CompareAndSwap(cur, next) {
			return
		}
	}
}

func contextBytes(ctx eval.Context) int {
	n := 0
	for k, v := range ctx {
		n += len(k) + valueBytes(v)
	}
	return n
}

func entryBytes(e *entry) int {
	n := len(e.App) + len(e.Environment) + len(e.ContextKey)
	for k, v := range e.Context {
		n += len(k) + valueBytes(v)
	}
	for k, v := range e.AttributeTypes {
		n += len(k) + len(v)
	}
	for _, a := range e.Attributes {
		n += len(a)
	}
	return n
}

func valueBytes(v any) int {
	switch t := v.(type) {
	case string:
		return len(t)
	case json.Number:
		return len(t.String())
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return 0
		}
		return len(b)
	}
}

func truncate(s string) string {
	if utf8.RuneCountInString(s) <= MaxValueLength {
		return s
	}
	runes := []rune(s)
	return string(runes[:MaxValueLength])
}

// contextKey is the document identity: the original targeting key, or the sha256 of the
// canonical untruncated context when there is none. Stored values may be truncated later.
func (c *Collector) contextKey(ctx eval.Context) string {
	if tk, ok := ctx[eval.TargetingKey].(string); ok && tk != "" {
		if _, skip := c.exclude[eval.TargetingKey]; !skip {
			return tk
		}
	}
	identity := make(map[string]any, len(ctx))
	for k, v := range ctx {
		if _, skip := c.exclude[k]; skip {
			continue
		}
		switch t := v.(type) {
		case string, bool, float64, json.Number:
			identity[k] = t
		default:
			b, err := json.Marshal(t)
			if err != nil {
				continue
			}
			identity[k] = string(b)
		}
	}
	// encoding/json sorts map keys, so this is a canonical form of the untruncated context.
	canonical, _ := json.Marshal(identity)
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func (c *Collector) toEntry(o observation) *entry {
	e := &entry{
		App:            o.app,
		Environment:    o.env,
		ContextKey:     c.contextKey(o.ctx),
		Context:        make(map[string]any, len(o.ctx)),
		AttributeTypes: make(map[string]string, len(o.ctx)),
		lastSeen:       o.at,
	}
	for k, v := range o.ctx {
		if _, skip := c.exclude[k]; skip {
			continue
		}
		switch t := v.(type) {
		case string:
			e.Context[k] = truncate(t)
			e.AttributeTypes[k] = TypeString
		case bool:
			e.Context[k] = t
			e.AttributeTypes[k] = TypeBoolean
		case float64, json.Number:
			e.Context[k] = t
			e.AttributeTypes[k] = TypeNumber
		default:
			// Lists are stored in their JSON form.
			b, err := json.Marshal(t)
			if err != nil {
				continue
			}
			e.Context[k] = truncate(string(b))
			e.AttributeTypes[k] = TypeString
		}
		e.Attributes = append(e.Attributes, k)
	}
	slices.Sort(e.Attributes)
	if e.Attributes == nil {
		e.Attributes = []string{}
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
	defer func() {
		for _, e := range entries {
			c.release(e.size)
		}
	}()

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
	batch := map[string]time.Time{}
	newPerScope := map[string]int{}
	sampledOut := 0
	written := 0
	failed := 0
	send := func() {
		if len(batch) == 0 {
			return
		}
		ok, bad := c.sendBulk(ctx, buf.Bytes(), batch)
		written += ok
		failed += bad
		buf.Reset()
		batch = map[string]time.Time{}
	}
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
		var op bytes.Buffer
		if err := writeBulkUpdate(&op, c.opts.Index, id, body); err != nil {
			c.log.Warn().Err(err).Msg("failed to encode observed context")
			continue
		}
		// A single document larger than the limit is sent alone. Several documents share a request
		// only while the body stays within MaxBulkBytes.
		if buf.Len() > 0 && buf.Len()+op.Len() > c.opts.MaxBulkBytes {
			send()
		}
		buf.Write(op.Bytes())
		batch[id] = e.lastSeen
	}
	send()
	if sampledOut > 0 {
		c.log.Debug().Int("sampled_out", sampledOut).Msg("new observed contexts over the per-flush limit were dropped")
	}
	if written+failed == 0 {
		return
	}
	c.trimKnown()
	c.log.Debug().Int("written", written).Int("failed", failed).Msg("observed contexts flushed")
}

func (c *Collector) sendBulk(ctx context.Context, body []byte, written map[string]time.Time) (int, int) {
	data, err := c.client.Bulk(ctx, body)
	if err != nil {
		c.log.Warn().Err(err).Int("contexts", len(written)).Msg("failed to write observed contexts")
		return 0, len(written)
	}
	var resp bulkResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		c.log.Warn().Err(err).Msg("failed to decode observed contexts bulk response")
		return 0, len(written)
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
	return len(written) - failed, failed
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
