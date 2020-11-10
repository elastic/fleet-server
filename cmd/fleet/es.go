// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/env"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/rs/zerolog/log"
)

type InfoResponse struct {
	ClusterName string `json:"cluster_name"`
	ClusterUUID string `json:"cluster_uuid"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
}

func Info(ctx context.Context, es *elasticsearch.Client) (*InfoResponse, error) {
	// Validate the connection
	res, err := es.Info()

	if err != nil {
		return nil, err
	}

	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("info fail %v", res)
	}

	var resp InfoResponse

	d := json.NewDecoder(res.Body)
	if err = d.Decode(&resp); err != nil {
		return nil, err
	}

	return &resp, err
}

func InitES(ctx context.Context) (*elasticsearch.Client, bulk.Bulk) {

	addr := strings.Split(env.ESUrl("https://localhost:9200"), ",")
	user := env.ESUsername("elastic")
	pass := env.ESPassword("changeme")
	mcph := env.ESMaxConnsPerHost(128)
	skip := env.ESSkipVerify(false)

	log.Debug().
		Strs("addr", addr).
		Str("user", user).
		Int("maxConnsPersHost", mcph).
		Bool("tlsSkipVerify", skip).
		Msg("init es")

	// TODO: config via kibana cfg
	es, err := elasticsearch.NewClient(
		elasticsearch.Config{
			Addresses: addr,
			Username:  user,
			Password:  pass,
			Transport: &http.Transport{
				MaxConnsPerHost:       mcph,
				MaxIdleConnsPerHost:   32,
				TLSHandshakeTimeout:   time.Second * 10,
				IdleConnTimeout:       60 * time.Second,
				ResponseHeaderTimeout: time.Second * 60,
				DialContext:           (&net.Dialer{Timeout: time.Second * 10}).DialContext,
				TLSClientConfig: &tls.Config{
					MinVersion:         tls.VersionTLS11,
					InsecureSkipVerify: skip,
				},
			},
		})
	checkErr(err)

	// Validate connection
	resp, err := Info(ctx, es)
	checkErr(err)

	log.Info().
		Str("name", resp.ClusterName).
		Str("uuid", resp.ClusterUUID).
		Str("vers", resp.Version.Number).
		Msg("Cluster Info")

	flushInterval := env.BulkFlushInterval(time.Millisecond * 250)

	blk := bulk.NewBulker(es)
	go func() {
		err := blk.Run(ctx, bulk.WithFlushInterval(flushInterval))
		log.Info().Err(err).Msg("Bulker exit")
	}()

	return es, blk
}
