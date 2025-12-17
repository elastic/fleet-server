// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package model

import "time"

// OpAmpAgent represents an OpenTelemetry Collector registered via OpAmp
type OpAmpAgent struct {
	ESDocument
	Timestamp  time.Time      `json:"@timestamp"`
	OpAmp      OpAmpData      `json:"opamp"`
	Connection ConnectionData `json:"connection"`
	Agent      AgentInfo      `json:"agent"`
	Host       HostInfo       `json:"host,omitempty"`
}

// OpAmpData contains the OpAmp-specific agent information
type OpAmpData struct {
	Agent              OpAmpAgentInfo        `json:"agent"`
	Status             string                `json:"status"`
	Health             *OpAmpHealth          `json:"health,omitempty"`
	Capabilities       []string              `json:"capabilities,omitempty"`
	EffectiveConfig    *OpAmpEffectiveConfig `json:"effective_config,omitempty"`
	RemoteConfigStatus *OpAmpConfigStatus    `json:"remote_config_status,omitempty"`
	SequenceNum        uint64                `json:"sequence_num"`
}

// OpAmpAgentInfo contains identifying information about the OpAmp agent
type OpAmpAgentInfo struct {
	InstanceUID              string            `json:"instance_uid"`
	Type                     string            `json:"type,omitempty"`
	Version                  string            `json:"version,omitempty"`
	IdentifyingAttributes    map[string]string `json:"identifying_attributes,omitempty"`
	NonIdentifyingAttributes map[string]string `json:"non_identifying_attributes,omitempty"`
}

// OpAmpHealth represents the health status of an OpAmp agent
type OpAmpHealth struct {
	Healthy            bool                    `json:"healthy"`
	StartTimeUnixNano  uint64                  `json:"start_time_unix_nano,omitempty"`
	LastError          string                  `json:"last_error,omitempty"`
	Status             string                  `json:"status,omitempty"`
	StatusTimeUnixNano uint64                  `json:"status_time_unix_nano,omitempty"`
	ComponentHealth    map[string]*OpAmpHealth `json:"component_health_map,omitempty"`
}

// OpAmpEffectiveConfig contains the effective configuration of an OpAmp agent
type OpAmpEffectiveConfig struct {
	Hash      string `json:"hash,omitempty"`
	ConfigMap []byte `json:"config_map,omitempty"` // Raw config bytes
}

// OpAmpConfigStatus represents the remote configuration status
type OpAmpConfigStatus struct {
	LastConfigHash string `json:"last_config_hash,omitempty"`
	Status         string `json:"status"` // APPLIED, APPLYING, FAILED
	ErrorMessage   string `json:"error_message,omitempty"`
}

// ConnectionData represents the connection information for an OpAmp agent
type ConnectionData struct {
	LastSeen    time.Time `json:"last_seen"`
	ConnectedAt time.Time `json:"connected_at,omitempty"`
	ServerID    string    `json:"server_id,omitempty"`
	Protocol    string    `json:"protocol"`
}

// AgentInfo represents basic agent information (ECS compatible)
type AgentInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name,omitempty"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
}

// HostInfo represents host information (ECS compatible)
type HostInfo struct {
	Hostname string  `json:"hostname,omitempty"`
	OS       *OSInfo `json:"os,omitempty"`
}

// OSInfo represents operating system information
type OSInfo struct {
	Type    string `json:"type,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

