// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// +build integration

package testing

import (
	"context"
	"testing"

	"github.com/elastic/go-ucfg/yaml"
	"github.com/rs/xid"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/config"
	"fleet/internal/pkg/esboot"
)

var defaultCfg config.Config
var defaultCfgData = []byte(`
output:
  elasticsearch:
    hosts: '${ELASTICSEARCH_HOSTS:localhost:9200}'
    username: '${ELASTICSEARCH_USERNAME:elastic}'
    password: '${ELASTICSEARCH_PASSWORD:changeme}'
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

func SetupBulk(ctx context.Context, t *testing.T, opts ...bulk.BulkOpt) bulk.Bulk {
	t.Helper()
	_, bulker, err := bulk.InitES(ctx, &defaultCfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return bulker
}

func SetupIndex(ctx context.Context, t *testing.T, bulker bulk.Bulk, mapping string) string {
	t.Helper()
	index := xid.New().String()
	err := esboot.EnsureIndex(ctx, bulker.Client(), index, mapping)
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
