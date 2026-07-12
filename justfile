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

venv:
    cd python && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

train-test: venv
    cd python && ./venv/bin/python test_trainer.py
