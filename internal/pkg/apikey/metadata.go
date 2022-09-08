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

// Metadata is additional information associated with an APIKey.
type Metadata struct {
	AgentID    string `json:"agent_id,omitempty"`
	Managed    bool   `json:"managed,omitempty"`
	ManagedBy  string `json:"managed_by,omitempty"`
	OutputName string `json:"output_name,omitempty"`
	Type       string `json:"type,omitempty"`
}

// NewMetadata returns Metadata for the given agentID.
func NewMetadata(agentID string, outputName string, typ Type) Metadata {
	return Metadata{
		AgentID:    agentID,
		Managed:    true,
		ManagedBy:  ManagedByFleetServer,
		OutputName: outputName,
		Type:       typ.String(),
	}
}
