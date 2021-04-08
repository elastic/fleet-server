// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"encoding/json"

	"github.com/elastic/fleet-server/v7/internal/pkg/model"
	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

type RoleT struct {
	Raw  []byte
	Sha2 string
}

type RoleMapT map[string]RoleT

type ParsedPolicy struct {
	Policy model.Policy
	Fields map[string]json.RawMessage
	Roles  RoleMapT
}

func NewParsedPolicy(p model.Policy) (*ParsedPolicy, error) {
	var err error

	var fields map[string]json.RawMessage
	if err = json.Unmarshal(p.Data, &fields); err != nil {
		return nil, err
	}

	// Interpret the output permissions if available
	var roles map[string]RoleT
	if perms := fields[FieldOutputPermissions]; len(perms) != 0 {
		if roles, err = parsePerms(perms); err != nil {
			return nil, err
		}
	}

	// We are cool and the gang
	pp := &ParsedPolicy{
		Policy: p,
		Fields: fields,
		Roles:  roles,
	}

	return pp, nil
}

func parsePerms(permsRaw json.RawMessage) (RoleMapT, error) {
	permMap, err := smap.Parse(permsRaw)
	if err != nil {
		return nil, err
	}

	// iterate across the keys
	m := make(RoleMapT, len(permMap))
	for k := range permMap {

		v := permMap.GetMap(k)

		if v != nil {
			var r RoleT

			// Stable hash on permissions payload
			if r.Sha2, err = v.Hash(); err != nil {
				return nil, err
			}

			// Re-marshal, the payload for each section
			if r.Raw, err = json.Marshal(v); err != nil {
				return nil, err
			}
			m[k] = r
		}
	}

	return m, nil
}
