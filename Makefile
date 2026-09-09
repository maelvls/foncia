STATICCHECK = honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: build test vet lint run clean

build:
	go build -o foncia .

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run $(STATICCHECK) ./...

run:
	go run . $(ARGS)

clean:
	rm -f foncia
	go clean -testcache
