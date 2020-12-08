package dl

import "fleet/internal/pkg/dsl"

// PrepareQueryAllAPIKeys prepares a query. For migration only.
func PrepareQueryAllAPIKeys(size uint64) ([]byte, error) {
	tmpl := dsl.NewTmpl()

	root := dsl.NewRoot()
	root.Size(size)

	err := tmpl.Resolve(root)
	if err != nil {
		return nil, err
	}
	return tmpl.Render(nil)
}
