// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"
	"time"

	"github.com/elastic/go-ucfg/yaml"
	"github.com/rs/xid"

	"github.com/Pallinder/go-randomdata"
	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/rs/zerolog"
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

const testPolicy = `{
	"properties": {
		"intval": {
			"type": "integer"
		},
		"objval": {
			"type": "object"
		},
		"boolval": {
			"type": "boolean"
		},
		"kwval": {
			"type": "keyword"
		},
		"binaryval": {
			"type": "binary"
		},
		"dateval": {
			"type": "date"
		}		
	}
}`

type subT struct {
	SubString string `json:"substring"`
}

type testT struct {
	IntVal    int    `json:"intval"`
	ObjVal    subT   `json:"objval"`
	BoolVal   bool   `json:"boolval"`
	KWVal     string `json:"kwval"`
	BinaryVal string `json:"binaryval"`
	DateVal   string `json:"dateval"`
}

func NewRandomSample() testT {

	return testT{
		IntVal:    int(rand.Int31()),
		ObjVal:    subT{SubString: randomdata.SillyName()},
		BoolVal:   (rand.Intn(1) == 1),
		KWVal:     randomdata.SillyName(),
		BinaryVal: base64.StdEncoding.EncodeToString([]byte(randomdata.SillyName())),
		DateVal:   time.Now().Format(time.RFC3339),
	}
}

func (ts testT) marshal(t testing.TB) []byte {
	data, err := json.Marshal(&ts)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (ts *testT) read(t testing.TB, bulker Bulk, ctx context.Context, index, id string) {
	data, err := bulker.Read(ctx, index, id)
	if err != nil {
		t.Fatal(err)
	}

	err = json.Unmarshal(data, ts)
	if err != nil {
		t.Fatal(err)
	}
}

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

func SetupBulk(ctx context.Context, t testing.TB, opts ...BulkOpt) Bulk {
	t.Helper()
	_, bulker, err := InitES(ctx, &defaultCfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return bulker
}

func SetupIndex(ctx context.Context, t testing.TB, bulker Bulk, mapping string) string {
	t.Helper()
	index := xid.New().String()
	err := esutil.EnsureIndex(ctx, bulker.Client(), index, mapping)
	if err != nil {
		t.Fatal(err)
	}
	return index
}

func SetupIndexWithBulk(ctx context.Context, t testing.TB, mapping string, opts ...BulkOpt) (string, Bulk) {
	t.Helper()
	bulker := SetupBulk(ctx, t, opts...)
	index := SetupIndex(ctx, t, bulker, mapping)
	return index, bulker
}

func QuietLogger() func() {
	l := zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	return func() {
		zerolog.SetGlobalLevel(l)
	}
}

func EqualElastic(werr, gerr error) bool {
	if werr == gerr {
		return true
	}

	wantErr, ok1 := werr.(es.ErrElastic)
	gotErr, ok2 := gerr.(*es.ErrElastic)

	if !ok2 {
		if tryAgain, ok3 := gerr.(es.ErrElastic); ok3 {
			gotErr = &tryAgain
			ok2 = true
		}
	}

	return (ok1 && ok2 && wantErr.Status == gotErr.Status && wantErr.Type == gotErr.Type)
}
