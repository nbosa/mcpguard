module mcpguard

go 1.23

require (
	github.com/spf13/cobra v1.10.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

// The Apple Foundation Models classifier (internal/proxy/classifier/foundationmodels.go)
// imports github.com/blacktop/go-foundationmodels behind a build tag and is
// therefore not listed above. To build a binary with the FM classifier enabled:
//
//   go get github.com/blacktop/go-foundationmodels@v0.1.8
//   CGO_ENABLED=1 go build -tags foundationmodels -o mcpguard ./cmd/mcpguard
