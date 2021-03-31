// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

const fleetAgent = "fleet-agent"

type Type int

const (
	TypeAccess Type = iota
	TypeOutput
)

func (t Type) String() string {
	return []string{"access", "output"}[t]
}

type Metadata struct {
	Application string `json:"application"`
	AgentId     string `json:"agent_id"`
	Type        string `json:"type"`
}

func NewMetadata() Metadata {
	return Metadata{
		Application: fleetAgent,
	}
}

type MetadataFunc func(m *Metadata)

func WithAgentId(agentId string) MetadataFunc {
	return func(m *Metadata) {
		m.AgentId = agentId
	}
}

func WithType(t Type) MetadataFunc {
	return func(m *Metadata) {
		m.Type = t.String()
	}
}
