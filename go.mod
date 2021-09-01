module github.com/elastic/fleet-server/v7

go 1.16

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/dgraph-io/ristretto v0.1.0
	github.com/elastic/beats/v7 v7.11.1
	github.com/elastic/elastic-agent-client/v7 v7.0.0-20210727140539-f0905d9377f6
	github.com/elastic/go-elasticsearch/v7 v7.5.1-0.20210823155509-845c8efe54a7
	github.com/elastic/go-ucfg v0.8.3
	github.com/gofrs/uuid v3.3.0+incompatible
	github.com/google/go-cmp v0.4.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-version v1.3.0
	github.com/hashicorp/golang-lru v0.5.2-0.20190520140433-59383c442f7d
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mailru/easyjson v0.7.7
	github.com/miolini/datacounter v1.0.2
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.2.1
	github.com/rs/zerolog v1.19.0
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.6.1
	go.uber.org/zap v1.14.0
	golang.org/x/sync v0.0.0-20200625203802-6e8e738ad208
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
)
