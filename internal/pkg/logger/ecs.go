// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package logger

const (

	// Basic logging
	EcsLogLevel      = "log.level"
	EcsLogName       = "log.logger"
	EcsLogCaller     = "log.origin"
	EcsLogStackTrace = "log.origin.stack_trace"
	EcsMessage       = "message"
	EcsTimestamp     = "@timestamp"
	EcsErrorMessage  = "error.message"

	// HTTP
	EcsHttpVersion           = "http.version"
	EcsHttpRequestId         = "http.request.id"
	EcsHttpRequestMethod     = "http.request.method"
	EcsHttpRequestBodyBytes  = "http.request.body.bytes"
	EcsHttpResponseCode      = "http.response.status_code"
	EcsHttpResponseBodyBytes = "http.response.body.bytes"

	// URL
	EcsUrlFull   = "url.full"
	EcsUrlDomain = "url.domain"
	EcsUrlPort   = "url.port"

	// Client
	EcsClientAddress = "client.address"
	EcsClientIp      = "client.ip"
	EcsClientPort    = "client.port"

	// Server
	EcsServerAddress = "server.address"

	// TLS
	EcsTlsEstablished        = "tls.established"
	EcsTlsResumed            = "tls.resumed"
	EcsTlsVersion            = "tls.version"
	EcsTlsClientServerName   = "tls.client.server_name"
	EcsTlsCipher             = "tls.cipher"
	EcsTlsClientIssuer       = "tls.client.issuer"
	EcsTlsClientSubject      = "tls.client.subject"
	EcsTlsClientNotBefore    = "tls.client.not_before"
	EcsTlsClientNotAfter     = "tls.client.not_after"
	EcsTlsClientSerialNumber = "tls.client.x509.serial_number"
	EcsTlsClientTimeFormat   = "2006-01-02T15:04:05.999Z"

	// Event
	EcsEventDuration = "event.duration"

	// Service
	EcsServiceName = "service.name"
)

// Non ECS compliant contants used in logging

const (
	ApiKeyId              = "fleet.apikey.id"
	PolicyId              = "fleet.policy.id"
	AgentId               = "fleet.agent.id"
	EnrollApiKeyId        = "fleet.enroll.apikey.id"
	AccessApiKeyId        = "fleet.access.apikey.id"
	DefaultOutputApiKeyId = "fleet.default.apikey.id"
)
