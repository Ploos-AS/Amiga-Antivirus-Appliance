BINARY ?= aaa

.PHONY: all test build build-arm64 fmt vet clean

all: test build

test:
	go test ./...

build:
	go build -o $(BINARY) ./cmd/aaa

build-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o $(BINARY)-linux-arm64 ./cmd/aaa

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-arm64
