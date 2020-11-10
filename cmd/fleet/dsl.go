// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"fleet/internal/pkg/dsl"
	"fleet/internal/pkg/saved"
)

const (
	kTmplApiKeyField  = "ApiKeyId"
	kTmplAgentIdField = "AgentIdList"
)

var apiKeyQueryTmpl = genQueryTemplate()

func genQueryTemplate() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	token := tmpl.Bind(kTmplApiKeyField)

	root := saved.NewQuery(AGENT_SAVED_OBJECT_TYPE)

	field := saved.ScopeField(AGENT_SAVED_OBJECT_TYPE, "access_api_key_id")
	root.Query().Bool().Must().Term(field, token, nil)

	if err := tmpl.Resolve(root); err != nil {
		panic(err)
	}

	return tmpl
}

var agentActionQueryTmpl = genAgentActionQueryTemplate()

func genAgentActionQueryTemplate() *dsl.Tmpl {
	tmpl := dsl.NewTmpl()
	token := tmpl.Bind(kTmplAgentIdField)

	root := saved.NewQuery(AGENT_ACTION_SAVED_OBJECT_TYPE)

	fieldSentAt := saved.ScopeField(AGENT_ACTION_SAVED_OBJECT_TYPE, "sent_at")
	fieldAgentId := saved.ScopeField(AGENT_ACTION_SAVED_OBJECT_TYPE, "agent_id")

	root.Query().Bool().Must().Terms(fieldAgentId, token, nil)
	root.Query().Bool().MustNot().Exists(fieldSentAt)

	if err := tmpl.Resolve(root); err != nil {
		panic(err)
	}

	return tmpl
}
