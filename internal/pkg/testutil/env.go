// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package testutil

import "os"

type Environment struct {
	Username string
	Password string
}

func GetEnvironment() Environment {
	return Environment{
		Username: os.Getenv("ELASTICSEARCH_USERNAME"),
		Password: os.Getenv("ELASTICSEARCH_PASSWORD"),
	}

}
