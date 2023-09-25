// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package api_version

// enrollMetadataTpl is the template for enrollement metadata
// It defines elastic.agent.version as that attribute is required by Kibana to successfully request diagnostics from an agent.
// A diagnostics request is used when testing the file-upload endpoints.
const enrollMetadataTpl = `{"elastic":{"agent":{"version":"%s"}}}`
