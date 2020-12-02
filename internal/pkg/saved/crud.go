// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"context"
	"encoding/json"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

const (
	kIndexKibana      = ".kibana"
	kMigrationVersion = "7.9.0" // TODO: bring in during build
)

type Hit struct {
	Id         string
	Type       string
	Space      string
	References []string
	UpdatedAt  string
	Data       json.RawMessage
}

type UpdateT struct {
	Id     string
	Type   string
	Fields map[string]interface{}
}

type CRUD interface {
	Create(ctx context.Context, ty string, src interface{}, opts ...Option) (id string, err error)
	Read(ctx context.Context, ty, id string, dst interface{}, opts ...Option) error

	// AAD or Encrypted fields not supported; you will break your saved object; don't do that.
	Update(ctx context.Context, ty, id string, fields map[string]interface{}, opts ...Option) error
	MUpdate(ctx context.Context, updates []UpdateT, opts ...Option) error

	FindByField(ctx context.Context, ty string, fields map[string]interface{}) ([]Hit, error)
	FindByNode(ctx context.Context, node *dsl.Node) ([]Hit, error)
	FindRaw(ctx context.Context, json []byte) ([]Hit, error)
	Decode(hit Hit, dst interface{}) error

	Client() *elasticsearch.Client
}

type mgr struct {
	idx bulk.Bulk
	key string
}

func NewMgr(idx bulk.Bulk, key string) CRUD {
	return &mgr{idx, key}
}

func (m *mgr) Client() *elasticsearch.Client {
	return m.idx.Client()
}

func (m *mgr) Create(ctx context.Context, ty string, src interface{}, options ...Option) (id string, err error) {
	opts, err := processOpts(options...)

	if err != nil {
		return
	}

	if err = validateType(ty); err != nil {
		return
	}

	if id, err = genID(opts); err != nil {
		return
	}

	var data []byte
	if data, err = m.encode(ty, id, opts.Space, src); err != nil {
		return
	}

	docID := fmtID(ty, id, opts.Space)

	nowStr := time.Now().UTC().Format(time.RFC3339)

	// TODO: hardcoded migration version
	var objMap = map[string]interface{}{
		ty:           json.RawMessage(data),
		"type":       ty,
		"updated_at": nowStr,
		"migrationVersion": map[string]string{
			"config": kMigrationVersion,
		},
		"references": opts.References,
	}

	if opts.Space != "" {
		objMap["namespace"] = opts.Space
	}

	var source []byte
	if source, err = json.Marshal(objMap); err != nil {
		return
	}

	bulkOpts := m.makeBulkOpts(opts)

	if opts.Overwrite {
		id, err = m.idx.Index(ctx, kIndexKibana, docID, source, bulkOpts...)
	} else {
		id, err = m.idx.Create(ctx, kIndexKibana, docID, source, bulkOpts...)
	}

	log.Trace().Err(err).RawJSON("source", source).Msg("On create")

	return
}

func (m *mgr) makeBulkOpts(opts optionsT) []bulk.Opt {
	var bulkOpts []bulk.Opt
	if opts.Refresh {
		bulkOpts = append(bulkOpts, bulk.WithRefresh())
	}
	return bulkOpts
}

func (m *mgr) Read(ctx context.Context, ty, id string, dst interface{}, options ...Option) error {
	opts, err := processOpts(options...)
	if err != nil {
		return err
	}

	if err := validateType(ty); err != nil {
		return err
	}

	if err := validateId(id); err != nil {
		return err
	}

	docId := fmtID(ty, id, opts.Space)

	payload, err := m.idx.Read(ctx, kIndexKibana, docId, bulk.WithRefresh())
	if err != nil {
		return err
	}

	var tmap map[string]json.RawMessage
	if err = json.Unmarshal(payload, &tmap); err != nil {
		return err
	}

	obj, ok := tmap[ty]
	if !ok {
		return ErrMalformedSavedObj
	}

	return m.decode(ty, id, opts.Space, obj, dst)
}

// Warning: If you pass encrypted or AAD fields, you broke something.  Don't do that.
func (m *mgr) Update(ctx context.Context, ty, id string, fields map[string]interface{}, options ...Option) error {
	opts, err := processOpts(options...)
	if err != nil {
		return err
	}

	if err := validateType(ty); err != nil {
		return err
	}

	if err := validateId(id); err != nil {
		return err
	}

	docId := fmtID(ty, id, opts.Space)

	timeNow := time.Now().UTC().Format(time.RFC3339)

	source, err := json.Marshal(map[string]interface{}{
		"doc": map[string]interface{}{
			ty:           fields,
			"updated_at": timeNow,
		},
	})

	if err != nil {
		return err
	}

	bulkOpts := m.makeBulkOpts(opts)

	return m.idx.Update(ctx, kIndexKibana, docId, source, bulkOpts...)
}

// Warning: If you pass encrypted or AAD fields, you broke something.  Don't do that.
func (m *mgr) MUpdate(ctx context.Context, updates []UpdateT, options ...Option) error {
	opts, err := processOpts(options...)
	if err != nil {
		return err
	}

	timeNow := time.Now().UTC().Format(time.RFC3339)

	ops := make([]bulk.BulkOp, 0, len(updates))

	for _, u := range updates {

		if err := validateType(u.Type); err != nil {
			return err
		}

		if err := validateId(u.Id); err != nil {
			return err
		}

		docId := fmtID(u.Type, u.Id, opts.Space)

		source, err := json.Marshal(map[string]interface{}{
			"doc": map[string]interface{}{
				u.Type:       u.Fields,
				"updated_at": timeNow,
			},
		})

		if err != nil {
			return err
		}

		ops = append(ops, bulk.BulkOp{
			Id:    docId,
			Body:  source,
			Index: kIndexKibana,
		})
	}

	bulkOpts := m.makeBulkOpts(opts)

	return m.idx.MUpdate(ctx, ops, bulkOpts...)
}

// Simple term query; does NOT support find on encrypted field.
func (m *mgr) FindByField(ctx context.Context, ty string, fields map[string]interface{}) ([]Hit, error) {

	query := NewQuery(ty)
	mustNode := query.Query().Bool().Must()
	for f, v := range fields {
		mustNode.Term(ScopeField(ty, f), v, nil)
	}

	return m.FindByNode(ctx, query)
}

func (m *mgr) FindByNode(ctx context.Context, node *dsl.Node) ([]Hit, error) {
	body, err := json.Marshal(node)
	if err != nil {
		return nil, err
	}

	return m.FindRaw(ctx, body)
}

func (m *mgr) FindRaw(ctx context.Context, body []byte) ([]Hit, error) {

	searchHits, err := m.idx.Search(ctx, []string{kIndexKibana}, body)

	if err != nil {
		return nil, err
	}

	var hits []Hit

	for _, h := range searchHits.Hits {

		o, err := parseId(h.Id)
		if err != nil {
			return nil, err
		}

		// Decode the source, better way to do this?
		var src map[string]json.RawMessage
		if err := json.Unmarshal(h.Source, &src); err != nil {
			return nil, err
		}

		var t string
		if err := json.Unmarshal(src["type"], &t); err != nil {
			return nil, err
		}

		var space string
		if v, ok := src["namespace"]; ok {
			if err := json.Unmarshal(v, &space); err != nil {
				return nil, err
			}
		}

		if t != o.ty {
			return nil, ErrTypeMismatch
		}

		if space != o.ns {
			return nil, ErrSpaceMismatch
		}

		var refs []string
		if err := json.Unmarshal(src["references"], &refs); err != nil {
			return nil, err
		}

		var updatedAt string
		if err := json.Unmarshal(src["updated_at"], &updatedAt); err != nil {
			return nil, err
		}

		hits = append(hits, Hit{
			Id:         o.id,
			Type:       t,
			Space:      space,
			References: refs,
			UpdatedAt:  updatedAt,
			Data:       src[t],
		})

	}

	return hits, err
}

func (m *mgr) Decode(hit Hit, dst interface{}) error {
	return m.decode(hit.Type, hit.Id, hit.Space, hit.Data, dst)
}
