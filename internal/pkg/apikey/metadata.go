// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

const FleetAgentApplication = "fleet-agent"

type Type int

const (
	TypeAccess Type = iota
	TypeOutput
)

func (t Type) String() string {
	return []string{"access", "output"}[t]
}

type Metadata struct {
	Application string `json:"application,omitempty"`
	AgentId     string `json:"agent_id,omitempty"`
	Type        string `json:"type,omitempty"`
}
