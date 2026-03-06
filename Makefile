.PHONY: build test

build:
	go build -o gateway ./cmd/gateway

test:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | grep total | awk '{gsub(/%/,""); if ($$3 < 80) { printf "Coverage %.1f%% is below 80%%\n", $$3; exit 1 } else { printf "Coverage %.1f%% OK\n", $$3 }}'; exit $$?
