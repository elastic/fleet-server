// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package dl

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/elastic/fleet-server/v7/internal/pkg/bulk"
	"github.com/elastic/fleet-server/v7/internal/pkg/dsl"
	"github.com/elastic/fleet-server/v7/internal/pkg/es"
	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/rs/zerolog/log"
)

var (
	tmplSearchPolicyLeaders     *dsl.Tmpl
	initSearchPolicyLeadersOnce sync.Once
)

func prepareSearchPolicyLeaders() (*dsl.Tmpl, error) {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Terms(FieldId, tmpl.Bind(FieldId), nil)

	err := tmpl.Resolve(root)
	if err != nil {
		return nil, err
	}
	return tmpl, nil
}

// SearchPolicyLeaders returns all the leaders for the provided policies
func SearchPolicyLeaders(ctx context.Context, bulker bulk.Bulk, ids []string, opt ...Option) (leaders map[string]model.PolicyLeader, err error) {
	initSearchPolicyLeadersOnce.Do(func() {
		tmplSearchPolicyLeaders, err = prepareSearchPolicyLeaders()
		if err != nil {
			return
		}
	})

	o := newOption(FleetPoliciesLeader, opt...)
	data, err := tmplSearchPolicyLeaders.RenderOne(FieldId, ids)
	if err != nil {
		return
	}
	res, err := bulker.Search(ctx, o.indexName, data)
	if err != nil {
		if errors.Is(err, es.ErrIndexNotFound) {
			log.Debug().Str("index", o.indexName).Msg(es.ErrIndexNotFound.Error())
			err = nil
		}
		return
	}

	leaders = map[string]model.PolicyLeader{}
	for _, hit := range res.Hits {
		var l model.PolicyLeader
		err = hit.Unmarshal(&l)
		if err != nil {
			return
		}
		leaders[hit.Id] = l
	}
	return leaders, nil
}

// TakePolicyLeadership tries to take leadership of a policy
func TakePolicyLeadership(ctx context.Context, bulker bulk.Bulk, policyId, serverId, version string, opt ...Option) error {
	o := newOption(FleetPoliciesLeader, opt...)
	data, err := bulker.Read(ctx, o.indexName, policyId, bulk.WithRefresh())
	if err != nil && err != es.ErrElasticNotFound {
		return err
	}
	var l model.PolicyLeader
	found := false
	if err != es.ErrElasticNotFound {
		found = true
		err = json.Unmarshal(data, &l)
		if err != nil {
			return err
		}
	}
	if l.Server == nil {
		l.Server = &model.ServerMetadata{}
	}
	l.Server.Id = serverId
	l.Server.Version = version
	l.SetTime(time.Now().UTC())
	if found {
		data, err = json.Marshal(&struct {
			Doc model.PolicyLeader `json:"doc"`
		}{
			Doc: l,
		})
		if err != nil {
			return err
		}
		err = bulker.Update(ctx, o.indexName, policyId, data)
	} else {
		data, err = json.Marshal(&l)
		if err != nil {
			return err
		}
		_, err = bulker.Create(ctx, o.indexName, policyId, data)
	}
	if err != nil {
		return err
	}
	return nil
}

// ReleasePolicyLeadership releases leadership of a policy
func ReleasePolicyLeadership(ctx context.Context, bulker bulk.Bulk, policyId, serverId string, releaseInterval time.Duration, opt ...Option) error {
	o := newOption(FleetPoliciesLeader, opt...)
	data, err := bulker.Read(ctx, o.indexName, policyId, bulk.WithRefresh())
	if err == es.ErrElasticNotFound {
		// nothing to do
		return nil
	}
	if err != nil {
		return err
	}
	var l model.PolicyLeader
	err = json.Unmarshal(data, &l)
	if err != nil {
		return err
	}
	if l.Server.Id != serverId {
		// not leader anymore; nothing to do
		return nil
	}
	released := time.Now().UTC().Add(-releaseInterval)
	l.SetTime(released)
	data, err = json.Marshal(&struct {
		Doc model.PolicyLeader `json:"doc"`
	}{
		Doc: l,
	})
	if err != nil {
		return err
	}
	err = bulker.Update(ctx, o.indexName, policyId, data)
	if err == es.ErrElasticVersionConflict {
		// another leader took over; nothing to worry about
		return nil
	}
	return err
}
