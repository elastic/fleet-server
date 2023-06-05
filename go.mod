module github.com/elastic/fleet-server/v7

go 1.20

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/deepmap/oapi-codegen v1.12.4
	github.com/dgraph-io/ristretto v0.1.1
	github.com/elastic/elastic-agent-client/v7 v7.1.2
	github.com/elastic/elastic-agent-libs v0.3.7
	github.com/elastic/elastic-agent-system-metrics v0.6.1
	github.com/elastic/go-elasticsearch/v8 v8.7.0
	github.com/elastic/go-ucfg v0.8.6
	github.com/fxamacker/cbor/v2 v2.4.0
	github.com/go-chi/chi/v5 v5.0.8
	github.com/gofrs/uuid v4.3.1+incompatible
	github.com/google/go-cmp v0.5.9
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.2
	github.com/mailru/easyjson v0.7.7
	github.com/miolini/datacounter v1.0.3
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/prometheus/client_golang v1.15.0
	github.com/rs/xid v1.4.0
	github.com/rs/zerolog v1.29.0
	github.com/spf13/cobra v1.7.0
	github.com/stretchr/testify v1.8.2
	go.elastic.co/apm/module/apmchiv5/v2 v2.3.0
	go.elastic.co/apm/module/apmelasticsearch/v2 v2.3.0
	go.elastic.co/apm/module/apmhttp/v2 v2.3.0
	go.elastic.co/apm/module/apmprometheus/v2 v2.4.1
	go.elastic.co/apm/v2 v2.4.1
	go.elastic.co/ecszerolog v0.1.0
	go.uber.org/zap v1.24.0
	golang.org/x/sync v0.1.0
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.54.0
	google.golang.org/protobuf v1.30.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Microsoft/go-winio v0.6.0 // indirect
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/elastic/elastic-transport-go/v8 v8.2.0 // indirect
	github.com/elastic/go-licenser v0.4.1 // indirect
	github.com/elastic/go-structform v0.0.10 // indirect
	github.com/elastic/go-sysinfo v1.10.1 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jcchavezs/porto v0.4.0 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/magefile/mage v1.14.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.18 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/tklauser/go-sysconf v0.3.11 // indirect
	github.com/tklauser/numcpus v0.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.elastic.co/ecszap v1.0.1 // indirect
	go.elastic.co/fastjson v1.1.0 // indirect
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/mod v0.8.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/sys v0.7.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	howett.net/plist v1.0.0 // indirect
)

replace github.com/deepmap/oapi-codegen => github.com/michel-laterman/oapi-codegen v1.12.4
