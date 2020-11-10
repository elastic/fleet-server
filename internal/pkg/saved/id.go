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
