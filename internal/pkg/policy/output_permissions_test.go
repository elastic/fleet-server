// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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
		"fallback": [{
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
		}]
	}	
}
`
	fallbackPermissionsHash = "6ca4f8d194b1efdbe3d2b1c3c18a0ebb954f08ea74a861785e07848f44f43752"

	outputPermissions = `
{
    "default": {
        "nginx-logs-1": [
            {
                "names": [
                    "logs-nginx.access-*",
                    "logs-nginx.error-*"
                ],
                "privileges": [
                    "append"
                ]
            }
        ],
        "nginx-metrics-1": [
            {
                "names": [
                    "metrics-nginx.substatus-*"
                ],
                "privileges": [
                    "append"
                ]
            }
        ],
        "endpoint-policy1-part1": [
            {
                "names": [
                    ".logs-endpoint.diagnostic.collection-*"
                ],
                "privileges": [
                    "read"
                ]
            }
        ],
        "endpoint-policy1-part2": [
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
`
	outputPermissionsHash = "73a2d2ab58cbc977d87fa138cf13347d47be1bd59523c36b3db1b08baa0b762c"

	resultDescriptors = `
{
    "endpoint-policy1-part1": {
        "index": [
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
        "index": [
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
        "index": [
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
        "index": [
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
