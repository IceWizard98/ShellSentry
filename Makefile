.PHONY: build test lint run clean venv train-test py-test daemon

build:
	go -C go build -o ../ssentry ./cmd/ssentry

test:
	go -C go test ./...

lint:
	go -C go vet ./...

run: build
	./ssentry run

clean:
	rm -f ssentry
	go -C go clean

venv:
	cd python && python3 -m venv venv && ./venv/bin/pip install -r requirements.txt

train-test: venv
	cd python && ./venv/bin/python test_trainer.py

py-test: venv
	cd python && ./venv/bin/python -m unittest discover -p 'test_*.py'

daemon: venv
	./python/venv/bin/python python/daemon.py --config config.yaml
