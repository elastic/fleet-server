// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/elastic/fleet-server/v7/internal/pkg/smap"
)

const (
	DefaultOutputName         = "default"
	OutputPermissionsProperty = "output_permissions"
)

var (
	ErrOutputPermissionsNotFound = errors.New("output_permissions not found")
	ErrDefaultOutputNotFound     = errors.New("default output not found")
	ErrInvalidPermissionsFormat  = errors.New("invalid permissions format")
)

// The sample output permissions JSON from policy
// At the moment we are only generating the key for the default output,
// so the hashing will be on default output only
// {
//     "default": {
//         "fallback": [{
//             "names": [
//                 "logs-*",
//                 "metrics-*",
//                 "traces-*",
//                 ".logs-endpoint.diagnostic.collection-*"
//             ],
//             "privileges": [
//                 "auto_configure",
//                 "create_doc"
//             ]
//         }]
//     }
// }
//
// Expected to be translated into the roles descriptors format for create API key
// https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html
// For example:
// {
//     "fallback": {
//         "index": [
//             {
//                 "names": [
//                 "logs-*",
//                 "metrics-*",
//                 "traces-*",
//                 ".logs-endpoint.diagnostic.collection-*"
//                 ],
//                 "privileges": [
//                     "auto_configure",
//                     "create_doc"
//                 ]
//             }
//         ]
//     }
// }

func GetRoleDescriptors(outputPermissionsRaw []byte) (hash string, roles []byte, err error) {
	if len(outputPermissionsRaw) == 0 {
		return
	}

	output, err := getDefaultOutputMap(outputPermissionsRaw)
	if err != nil {
		return
	}

	res := make(smap.Map)

	for role, v := range output {
		permissions, ok := v.([]interface{})
		if !ok {
			return hash, roles, ErrInvalidPermissionsFormat
		}

		idx := make([]interface{}, 0, len(permissions))

		for _, permission := range permissions {
			idx = append(idx, permission)
		}

		m := make(smap.Map)
		m["index"] = idx
		res[role] = m
	}

	// Calculating the hash of the original output map
	hash, err = output.Hash()
	if err != nil {
		return
	}

	roles, err = json.Marshal(res)
	if err != nil {
		return
	}

	return
}

func CheckOutputPermissionsChanged(hash string, outputPermissionsRaw []byte) (newHash string, roles []byte, changed bool, err error) {
	if len(outputPermissionsRaw) == 0 {
		return
	}

	// shotcuircut, hash and compare as is, if equals the json is serialized consistently from jsacascript and go
	newHash, err = getDefaultOutputHash(outputPermissionsRaw)
	if err != nil {
		return
	}
	if hash == newHash {
		return hash, nil, false, nil
	}

	newHash, roles, err = GetRoleDescriptors(outputPermissionsRaw)
	if err != nil {
		return
	}

	return newHash, roles, (newHash != hash), nil
}

func getDefaultOutputHash(outputPermissionsRaw []byte) (hash string, err error) {
	var m map[string]json.RawMessage
	err = json.Unmarshal(outputPermissionsRaw, &m)
	if err != nil {
		return
	}

	if len(m[DefaultOutputName]) == 0 {
		return
	}

	b := sha256.Sum256(m[DefaultOutputName])
	return hex.EncodeToString(b[:]), nil
}

func getDefaultOutputMap(outputPermissionsRaw []byte) (defaultOutput smap.Map, err error) {
	outputPermissions, err := smap.Parse(outputPermissionsRaw)
	if err != nil {
		return
	}

	defaultOutput = outputPermissions.GetMap(DefaultOutputName)
	if defaultOutput == nil {
		err = ErrDefaultOutputNotFound
	}
	return
}
