// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"fleet/internal/pkg/model"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofrs/uuid"
)

// Action is a policy action that is sent as an action ID to an agent.
type Action struct {
	PolicyId       string
	RevisionIdx    int64
	CoordinatorIdx int64
}

// ActionFromPolicy creates the action from the policy.
func ActionFromPolicy(policy model.Policy) Action {
	return Action{
		PolicyId:       policy.PolicyId,
		RevisionIdx:    policy.RevisionIdx,
		CoordinatorIdx: policy.CoordinatorIdx,
	}
}

// ActionFromString converts the string to an action.
func ActionFromString(actionId string) (Action, bool) {
	split := strings.Split(actionId, ":")
	if len(split) != 4 {
		return Action{}, false
	}
	if split[0] != "policy" {
		return Action{}, false
	}
	if _, err := uuid.FromString(split[1]); err != nil {
		return Action{}, false
	}
	revIdx, err := strconv.ParseInt(split[2], 10, 64)
	if err != nil {
		return Action{}, false
	}
	coordIdx, err := strconv.ParseInt(split[3], 10, 64)
	if err != nil {
		return Action{}, false
	}
	return Action{
		PolicyId:       split[1],
		RevisionIdx:    revIdx,
		CoordinatorIdx: coordIdx,
	}, true
}

// String returns the ID string for the action.
func (a *Action) String() string {
	return fmt.Sprintf("policy:%s:%d:%d", a.PolicyId, a.RevisionIdx, a.CoordinatorIdx)
}
