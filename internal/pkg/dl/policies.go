package dl

import (
	"context"
	"encoding/json"
	"errors"

	"sync"

	"fleet/internal/pkg/bulk"
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/model"
)

var (
	tmplQueryLatestPolicies     *dsl.Tmpl
	initQueryLatestPoliciesOnce sync.Once
)

var ErrPolicyLeaderNotFound = errors.New("policy has no leader")

func prepareQueryLatestPolicies() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	root := dsl.NewRoot()
	root.Query().Bool().Filter().Term(FieldId, tmpl.Bind(FieldId), nil)

	return tmpl.MustResolve(root)
}

func QueryLatestPolicies(ctx context.Context, bulker bulk.Bulk, policyId string) (policies []model.Policy, err error) {
	initQueryLatestPoliciesOnce.Do(func() {
		tmplQueryLatestPolicies = prepareQueryLatestPolicies()
	})

	query, err := tmplQueryLatestPolicies.RenderOne(FieldId, policyId)
	if err != nil {
		return
	}

	res, err := bulker.Search(ctx, []string{FleetPoliciesLeader}, query)
	if err != nil {
		return
	}

	if len(res.Hits) == 0 {
		return leader, ErrAgentNotFound
	}

	hit := res.Hits[0]
	err = json.Unmarshal(hit.Source, &leader)

	return leader, err
}


