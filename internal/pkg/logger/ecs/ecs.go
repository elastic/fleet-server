// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ecs

const (

	// Basic logging
	LogLevel      = "log.level"
	LogName       = "log.logger"
	LogCaller     = "log.origin"
	LogStackTrace = "log.origin.stack_trace"
	Message       = "message"
	Timestamp     = "@timestamp"
	ErrorMessage  = "error.message"

	// HTTP
	HTTPVersion           = "http.version"
	HTTPRequestID         = "http.request.id"
	HTTPRequestMethod     = "http.request.method"
	HTTPRequestBodyBytes  = "http.request.body.bytes"
	HTTPResponseCode      = "http.response.status_code"
	HTTPResponseBodyBytes = "http.response.body.bytes"

	// URL
	URLFull   = "url.full"
	URLDomain = "url.domain"
	URLPort   = "url.port"

	// Client
	ClientAddress = "client.address"
	ClientIP      = "client.ip"
	ClientPort    = "client.port"

	// Server
	ServerAddress = "server.address"

	// TLS
	TLSEstablished        = "tls.established"
	TLSResumed            = "tls.resumed"
	TLSVersion            = "tls.version"
	TLSClientServerName   = "tls.client.server_name"
	TLSCipher             = "tls.cipher"
	TLSClientIssuer       = "tls.client.issuer"
	TLSClientSubject      = "tls.client.subject"
	TLSClientNotBefore    = "tls.client.not_before"
	TLSClientNotAfter     = "tls.client.not_after"
	TLSClientSerialNumber = "tls.client.x509.serial_number"
	TLSClientTimeFormat   = "2006-01-02T15:04:05.999Z"

	// Event
	EventDuration = "event.duration"

	// Service
	ServiceName = "service.name"
	ServiceType = "service.type"
)

// Non ECS compliant contants used in logging

const (
	APIKeyID              = "fleet.apikey.id" //nolint:gosec // key name
	PolicyID              = "fleet.policy.id"
	AgentID               = "fleet.agent.id"
	EnrollAPIKeyID        = "fleet.enroll.apikey.id"
	AccessAPIKeyID        = "fleet.access.apikey.id"
	DefaultOutputAPIKeyID = "fleet.default.apikey.id"
	ActionID              = "fleet.action.id"
	ActionType            = "fleet.action.type"
	PolicyOutputName      = "fleet.policy.output.name"
	RevisionIdx           = "fleet.revision_idx"
	CoordinatorIdx        = "fleet.coordinator_idx"
)
