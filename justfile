# Just recipes for Shell Sentry build tasks

build:
    go build -o ssentry ./cmd/ssentry

test:
    go test -v ./...

lint:
    go vet ./...

run: build
    ./ssentry

clean:
    rm -f ssentry
    go clean
