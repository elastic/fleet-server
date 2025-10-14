module github.com/elastic/fleet-server/v7

go 1.25.1

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/dgraph-io/ristretto v0.2.0
	github.com/docker/go-units v0.5.0
	github.com/elastic/elastic-agent-client/v7 v7.17.2
	github.com/elastic/elastic-agent-libs v0.24.1
	github.com/elastic/elastic-agent-system-metrics v0.13.2
	github.com/elastic/go-elasticsearch/v8 v8.19.0
	github.com/elastic/go-ucfg v0.8.8
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/go-chi/chi/v5 v5.2.3
	github.com/gofrs/uuid/v5 v5.3.2
	github.com/google/go-cmp v0.7.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-version v1.7.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/magefile/mage v1.15.0
	github.com/mailru/easyjson v0.9.1
	github.com/miolini/datacounter v1.0.3
	github.com/oapi-codegen/runtime v1.1.2
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/prometheus/client_golang v1.23.2
	github.com/rs/xid v1.6.0
	github.com/rs/zerolog v1.34.0
	github.com/spf13/cobra v1.10.1
	github.com/stretchr/testify v1.11.1
	go.elastic.co/apm/module/apmchiv5/v2 v2.7.1
	go.elastic.co/apm/module/apmelasticsearch/v2 v2.7.1
	go.elastic.co/apm/module/apmhttp/v2 v2.7.1
	go.elastic.co/apm/module/apmprometheus/v2 v2.7.1
	go.elastic.co/apm/module/apmzerolog/v2 v2.7.1
	go.elastic.co/apm/v2 v2.7.1
	go.elastic.co/ecszerolog v0.2.0
	go.uber.org/zap v1.27.0
	golang.org/x/net v0.46.0
	golang.org/x/sync v0.17.0
	golang.org/x/time v0.14.0
	google.golang.org/grpc v1.76.0
	google.golang.org/protobuf v1.36.10
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.7.0 // indirect
	github.com/elastic/go-structform v0.0.12 // indirect
	github.com/elastic/go-sysinfo v1.15.1 // indirect
	github.com/elastic/go-windows v1.0.2 // indirect
	github.com/elastic/gosigar v0.14.3 // indirect
	github.com/elastic/pkcs8 v1.0.0 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/shirou/gopsutil/v4 v4.24.7 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.elastic.co/ecszap v1.0.3 // indirect
	go.elastic.co/fastjson v1.5.1 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.43.0 // indirect
	golang.org/x/mod v0.28.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	golang.org/x/tools v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250804133106-a7a43d27e69b // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v1.0.1 // indirect
)
