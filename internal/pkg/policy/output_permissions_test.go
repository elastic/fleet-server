// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !integration
// +build !integration

package policy

import (
	"testing"

	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
	"github.com/google/go-cmp/cmp"
)

const (
	fallbackPermissions = `
	{
		"default": {
			"_fallback": {
				"indices": [
					{
						"names": [
							"logs-*",
							"metrics-*",
							"traces-*",
							".logs-endpoint.diagnostic.collection-*"
						],
						"privileges": [
							"auto_configure",
							"create_doc"
						]
					}
				]
			}
		}
	}	
`
	fallbackPermissionsHash = "48e2e1dfe0e64df0dd841e96e28bb82ff6273432e9ebccca259a3278ff86ee4c"

	outputPermissions = `
	{
		"default": {
			"nginx-logs-1": {
				"indices": [
					{
						"names": [
							"logs-nginx.access-*",
							"logs-nginx.error-*"
						],
						"privileges": [
							"append"
						]
					}
				]
			},
			"nginx-metrics-1": {
				"indices": [
					{
						"names": [
							"metrics-nginx.substatus-*"
						],
						"privileges": [
							"append"
						]
					}
				]
			},
			"endpoint-policy1-part1": {
				"indices": [
					{
						"names": [
							".logs-endpoint.diagnostic.collection-*"
						],
						"privileges": [
							"read"
						]
					}
				]
			},
			"endpoint-policy1-part2": {
				"indices": [
					{
						"names": [
							"metrics-endpoint-*"
						],
						"privileges": [
							"append"
						]
					}
				]
			}
		}
	}	
`
	outputPermissionsHash = "42c955b5df44eec374dc66a97ab8c2045a88583af499aba81345c4221e473ead"

	resultDescriptors = `
{
    "endpoint-policy1-part1": {
        "indices": [
            {
                "names": [
                    ".logs-endpoint.diagnostic.collection-*"
                ],
                "privileges": [
                    "read"
                ]
            }
        ]
    },
    "endpoint-policy1-part2": {
        "indices": [
            {
                "names": [
                    "metrics-endpoint-*"
                ],
                "privileges": [
                    "append"
                ]
            }
        ]
    },
    "nginx-logs-1": {
        "indices": [
            {
                "names": [
                    "logs-nginx.access-*",
                    "logs-nginx.error-*"
                ],
                "privileges": [
                    "append"
                ]
            }
        ]
    },
    "nginx-metrics-1": {
        "indices": [
            {
                "names": [
                    "metrics-nginx.substatus-*"
                ],
                "privileges": [
                    "append"
                ]
            }
        ]
    }
}
`
)

func TestGetRoleDescriptors(t *testing.T) {

	hash, roles, err := GetRoleDescriptors([]byte(outputPermissions))
	if err != nil {
		t.Fatal(err)
	}

	m, err := smap.Parse([]byte(resultDescriptors))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	diff := cmp.Diff(expected, roles)
	if diff != "" {
		t.Fatal(diff)
	}

	diff = cmp.Diff(outputPermissionsHash, hash)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestCheckOutputPermissionsChanged(t *testing.T) {
	// Detect change with initially empty hash
	hash, roles, changed, err := CheckOutputPermissionsChanged("", []byte(fallbackPermissions))
	if err != nil {
		t.Fatal(err)
	}
	diff := cmp.Diff(fallbackPermissionsHash, hash)
	if diff != "" {
		t.Error(diff)
	}

	if !changed {
		t.Error("expected policy hash change detected")
	}

	if len(roles) == 0 {
		t.Error("expected non empty roles descriptors")
	}

	// Detect no change with the same hash and the content
	newHash, roles, changed, err := CheckOutputPermissionsChanged(hash, []byte(fallbackPermissions))
	diff = cmp.Diff(hash, newHash)
	if diff != "" {
		t.Error(diff)
	}
	if changed {
		t.Error("expected policy hash no change detected")
	}

	// Detect the change with the new output permissions
	newHash, roles, changed, err = CheckOutputPermissionsChanged(hash, []byte(outputPermissions))
	diff = cmp.Diff(outputPermissionsHash, newHash)
	if diff != "" {
		t.Error(diff)
	}
	if !changed {
		t.Error("expected policy hash change detected")
	}
}
