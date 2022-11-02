module github.com/elastic/fleet-server/v7

go 1.16

require (
	github.com/Pallinder/go-randomdata v1.2.0
	github.com/dgraph-io/ristretto v0.1.1
	github.com/elastic/beats/v7 v7.11.2
	github.com/elastic/elastic-agent-client/v7 v7.0.0-20221102171927-bc376a4e0f9f
	github.com/elastic/go-elasticsearch/v7 v7.16.0
	github.com/elastic/go-licenser v0.4.1 // indirect
	github.com/elastic/go-ucfg v0.8.6
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/google/go-cmp v0.5.9
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-version v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/julienschmidt/httprouter v1.3.0
	github.com/mailru/easyjson v0.7.7
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/miolini/datacounter v1.0.3
	github.com/pbnjay/memory v0.0.0-20210728143218-7b4eea64cf58
	github.com/pkg/errors v0.9.1
	github.com/rs/xid v1.3.0
	github.com/rs/zerolog v1.27.0
	github.com/spf13/cobra v1.3.0
	github.com/stretchr/testify v1.7.0
	go.uber.org/zap v1.21.0
	golang.org/x/mod v0.6.0 // indirect
	golang.org/x/sync v0.0.0-20220929204114-8fcdb60fdcc0
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	google.golang.org/genproto v0.0.0-20221027153422-115e99e71e1c // indirect
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20200629123429-0e7b69039eec
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
)
