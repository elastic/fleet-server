// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
)

// Revision is a policy revision that is sent as an action ID to an agent.
type Revision struct {
	PolicyId       string
	RevisionIdx    int64
	CoordinatorIdx int64
}

// RevisionFromPolicy creates the revision from the policy.
func RevisionFromPolicy(policy model.Policy) Revision {
	return Revision{
		PolicyId:       policy.PolicyId,
		RevisionIdx:    policy.RevisionIdx,
		CoordinatorIdx: policy.CoordinatorIdx,
	}
}

// RevisionFromString converts the string to a policy revision.
func RevisionFromString(actionId string) (Revision, bool) {
	split := strings.Split(actionId, ":")
	if len(split) != 4 {
		return Revision{}, false
	}
	if split[0] != "policy" {
		return Revision{}, false
	}
	revIdx, err := strconv.ParseInt(split[2], 10, 64)
	if err != nil {
		return Revision{}, false
	}
	coordIdx, err := strconv.ParseInt(split[3], 10, 64)
	if err != nil {
		return Revision{}, false
	}
	return Revision{
		PolicyId:       split[1],
		RevisionIdx:    revIdx,
		CoordinatorIdx: coordIdx,
	}, true
}

// String returns the ID string for the policy revision.
func (a *Revision) String() string {
	return fmt.Sprintf("policy:%s:%d:%d", a.PolicyId, a.RevisionIdx, a.CoordinatorIdx)
}
