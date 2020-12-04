package config

const (
	FeatureActions = "actions"
)

type Features map[string]Feature

func (f Features) Enabled(name string) bool {
	if feature, ok := f[name]; ok {
		return feature.Enabled
	}
	return false
}

type Feature struct {
	Enabled bool `config:"enabled"`
}
