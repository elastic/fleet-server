// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package fleet

import (
	"fleet-server/internal/pkg/dsl"
	"fleet-server/internal/pkg/saved"
)

const (
	kTmplApiKeyField  = "ApiKeyId"
	kTmplAgentIdField = "AgentIdList"
)

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
