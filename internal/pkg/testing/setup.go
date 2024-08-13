// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package testing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-ucfg/yaml"
	"github.com/rs/xid"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
)

var defaultCfg config.Config
var defaultCfgData = []byte(`
output:
  elasticsearch:
    hosts: '${ELASTICSEARCH_HOSTS:localhost:9200}'
    service_token: '${ELASTICSEARCH_SERVICE_TOKEN:test-token}'
fleet:
  agent:
    id: 1e4954ce-af37-4731-9f4a-407b08e69e42
`)

func init() {
	c, err := yaml.NewConfig(defaultCfgData, config.DefaultOptions...)
	if err != nil {
		panic(err)
	}
	err = c.Unpack(&defaultCfg, config.DefaultOptions...)
	if err != nil {
		panic(err)
	}
}

func SetupES(ctx context.Context, t *testing.T) *elasticsearch.Client {
	t.Helper()

	cli, err := es.NewClient(ctx, &defaultCfg, false)
	if err != nil {
		t.Fatalf("Unable to create elasticsearch client: %v", err)
	}

	return cli
}

func SetupBulk(ctx context.Context, t *testing.T, opts ...bulk.BulkOpt) bulk.Bulk {
	t.Helper()

	cli := SetupES(ctx, t)
	opts = append(opts, bulk.BulkOptsFromCfg(&defaultCfg)...)
	bulker := bulk.NewBulker(cli, nil, opts...)
	go func() {
		_ = bulker.Run(ctx)
	}()
	return bulker
}

func SetupIndex(ctx context.Context, t *testing.T, bulker bulk.Bulk, mapping string) string {
	t.Helper()
	index := xid.New().String()
	err := esutil.EnsureIndex(ctx, bulker.Client(), index, mapping)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func SetupIndexWithBulk(ctx context.Context, t *testing.T, mapping string, opts ...bulk.BulkOpt) (string, bulk.Bulk) {
	t.Helper()
	bulker := SetupBulk(ctx, t, opts...)
	index := SetupIndex(ctx, t, bulker, mapping)
	return index, bulker
}

func SetupCleanIndex(ctx context.Context, t *testing.T, index string, opts ...bulk.BulkOpt) (string, bulk.Bulk) {
	bulker := SetupBulk(ctx, t, opts...)

	CleanIndex(ctx, t, bulker, index)

	return index, bulker
}

func CleanIndex(ctx context.Context, t *testing.T, bulker bulk.Bulk, index string) string {
	t.Helper()

	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().MatchAll()
	q := tmpl.MustResolve(root)

	query, err := q.Render(make(map[string]interface{}))
	if err != nil {
		t.Fatalf("could not clean index: failed to render query template: %v", err)
	}

	cli := bulker.Client()

	res, err := cli.API.DeleteByQuery([]string{index}, bytes.NewReader(query),
		cli.API.DeleteByQuery.WithContext(ctx),
		cli.API.DeleteByQuery.WithRefresh(true),
	)
	if err != nil {
		t.Fatalf("could not clean index %s, DeleteByQuery failed: %v",
			index, err)
	}
	defer res.Body.Close()

	var esres es.DeleteByQueryResponse
	err = json.NewDecoder(res.Body).Decode(&esres)
	if err != nil {
		t.Fatalf("could not decode ES response: %v", err)
	}

	if res.IsError() {
		err = es.TranslateError(res.StatusCode, esres.Error)
		if err != nil {
			if errors.Is(err, es.ErrIndexNotFound) {
				err = nil
			}
		}
	}
	if err != nil {
		t.Fatalf("ES returned an error: %v. body: %q", err, res)
	}

	return index
}
