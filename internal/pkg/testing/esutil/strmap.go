// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package esutil

type stringMap map[string]interface{}

func (m stringMap) GetMap(k string) stringMap {
	if m == nil {
		return m
	}

	v := m[k]
	if v != nil {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func (m stringMap) GetString(k string) string {
	if m == nil {
		return ""
	}
	if v := m[k]; v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
