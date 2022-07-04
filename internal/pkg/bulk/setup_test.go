// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package bulk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/Pallinder/go-randomdata"
	"github.com/elastic/go-ucfg/yaml"
	"github.com/rs/xid"

	"github.com/elastic/fleet-server/v7/internal/pkg/config"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/esutil"
	"github.com/elastic/fleet-server/v7/internal/pkg/testing/rnd"
)

var rand = rnd.New()

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

// environment tracks env vars that can be used for testing
type environment struct {
	Username string
	Password string
}

func getEnvironment() environment {
	return environment{
		Username: os.Getenv("ELASTICSEARCH_USERNAME"),
		Password: os.Getenv("ELASTICSEARCH_PASSWORD"),
	}
}

func NewRandomSample() testT {
	return testT{
		IntVal:    rand.Int(0, math.MaxInt32),
		ObjVal:    subT{SubString: randomdata.SillyName()},
		BoolVal:   rand.Bool(),
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

	// Set up the client with username and password since this test is generic for any index and uses it's own index/mapping
	e := getEnvironment()
	cli, err := es.NewClient(ctx, &defaultCfg, false, es.WithUsrPwd(e.Username, e.Password))
	if err != nil {
		t.Fatal(err)
	}

	opts = append(opts, BulkOptsFromCfg(&defaultCfg)...)

	bulker := NewBulker(cli, opts...)
	go func() { _ = bulker.Run(ctx) }()

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

func EqualElastic(werr, gerr error) bool {
	if errors.Is(werr, gerr) {
		return true
	}

	var wantErr es.ErrElastic
	if !errors.As(werr, &wantErr) {
		return false
	}

	var gotErr *es.ErrElastic
	ok2 := errors.As(gerr, &gotErr)
	if !ok2 {
		ok2 = errors.As(gerr, gotErr)
	}

	return (ok2 && wantErr.Status == gotErr.Status && wantErr.Type == gotErr.Type)
}
