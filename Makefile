STATICCHECK = honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: build dist test vet lint run clean

build:
	go build -o foncia .

# The binaries that the Dockerfile copies. Build the image where Docker runs,
# e.g. on the Pi: docker build -t ghcr.io/maelvls/foncia:latest .
dist:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/foncia-linux-arm64 .
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/foncia-linux-amd64 .

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run $(STATICCHECK) ./...

run:
	go run . $(ARGS)

clean:
	rm -rf foncia dist
	go clean -testcache
