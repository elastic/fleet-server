// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package apikey

const ManagedByFleetServer = "fleet-server"

type Type int

const (
	TypeAccess Type = iota
	TypeOutput
)

func (t Type) String() string {
	return []string{"access", "output"}[t]
}

type Metadata struct {
	AgentId   string `json:"agent_id,omitempty"`
	Managed   bool   `json:"managed,omitempty"`
	ManagedBy string `json:"managed_by,omitempty"`
	Type      string `json:"type,omitempty"`
}

func NewMetadata(agentId string, typ Type) Metadata {
	return Metadata{
		AgentId:   agentId,
		Managed:   true,
		ManagedBy: ManagedByFleetServer,
		Type:      typ.String(),
	}
}
