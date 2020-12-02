// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package saved

import (
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
)

func genID(opts optionsT) (string, error) {
	var id string

	if opts.Id != "" {
		id = opts.Id
	} else if u, err := uuid.NewV4(); err != nil {
		return "", err
	} else {
		id = u.String()
	}

	return id, nil
}

func fmtID(ty, id, space string) string {

	if space != "" {
		return fmt.Sprintf("%s:%s:%s", space, ty, id)
	}

	return fmt.Sprintf("%s:%s", ty, id)
}

type objectId struct {
	id string
	ns string
	ty string
}

// Deconstruct the ID.  Expect namespace:type:id
func parseId(id string) (o objectId, err error) {

	tuple := strings.Split(id, ":")

	switch len(tuple) {
	case 1:
		o.id = tuple[0]
	case 2:
		o.ty = tuple[0]
		o.id = tuple[1]
	case 3:
		o.ns = tuple[0]
		o.ty = tuple[1]
		o.id = tuple[2]
	default:
		err = ErrMalformedIdentifier
	}

	return
}
