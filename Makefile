.PHONY: build test lint clean

build:
	go build ./...

test:
	go test ./... -v -race -coverprofile=coverage.out

lint:
	golangci-lint run ./...

clean:
	go clean
	rm -f coverage.out

