// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

const (

	// Basic logging
	ECSLogLevel      = "log.level"
	ECSLogName       = "log.logger"
	ECSLogCaller     = "log.origin"
	ECSLogStackTrace = "log.origin.stack_trace"
	ECSMessage       = "message"
	ECSTimestamp     = "@timestamp"
	ECSErrorMessage  = "error.message"

	// HTTP
	ECSHTTPVersion           = "http.version"
	ECSHTTPRequestID         = "http.request.id"
	ECSHTTPRequestMethod     = "http.request.method"
	ECSHTTPRequestBodyBytes  = "http.request.body.bytes"
	ECSHTTPResponseCode      = "http.response.status_code"
	ECSHTTPResponseBodyBytes = "http.response.body.bytes"

	// URL
	ECSURLFull   = "url.full"
	ECSURLDomain = "url.domain"
	ECSURLPort   = "url.port"

	// Client
	ECSClientAddress = "client.address"
	ECSClientIP      = "client.ip"
	ECSClientPort    = "client.port"

	// Server
	ECSServerAddress = "server.address"

	// TLS
	ECSTLSEstablished        = "tls.established"
	ECSTLSsResumed           = "tls.resumed"
	ECSTLSVersion            = "tls.version"
	ECSTLSClientServerName   = "tls.client.server_name"
	ECSTLSCipher             = "tls.cipher"
	ECSTLSClientIssuer       = "tls.client.issuer"
	ECSTLSClientSubject      = "tls.client.subject"
	ECSTLSClientNotBefore    = "tls.client.not_before"
	ECSTLSClientNotAfter     = "tls.client.not_after"
	ECSTLSClientSerialNumber = "tls.client.x509.serial_number"
	ECSTLSClientTimeFormat   = "2006-01-02T15:04:05.999Z"

	// Event
	ECSEventDuration = "event.duration"

	// Service
	ECSServiceName = "service.name"
	ECSServiceType = "service.type"
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
)
