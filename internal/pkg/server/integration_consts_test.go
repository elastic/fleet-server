// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package server

// Literals shared by the integration tests.
const (
	tDefault           = "default"
	tDefaultTitle      = "Default"
	tOutputESDefault   = "elasticsearch/default"
	tOTLP              = "otlp"
	tEndpoint          = "endpoint"
	tSecrets           = "secrets"
	tAPIKey            = "api_key"
	tToken             = "token"
	tTLS               = "tls"
	tSSL               = "ssl"
	tKey               = "key"
	tHosts             = "hosts"
	tSourceURI         = "sourceURI"
	tFleet             = "fleet"
	tManaged           = "managed"
	tEnroll            = "enroll"
	tType              = "type"
	tManagedBy         = "managed_by"
	tPolicyID          = "policy_id"
	tPackageVarSecret  = "package_var_secret"
	tInlineSecretValue = "inline_secret_value"
	tPathSecretValue   = "path_secret_value"

	tRemoteES                  = "remoteES"
	tRemoteESName              = "RemoteES"
	tRemoteElasticsearch       = "remote_elasticsearch"
	tServiceToken              = "service_token"
	tSSLEnabled                = "ssl.enabled"
	tSSLCertificateAuthorities = "ssl.certificate_authorities"
	tMonitoring                = "monitoring"
	tUseOutput                 = "use_output"
)
