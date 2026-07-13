.PHONY: build test lint run clean venv train-test py-test daemon geo playground playground-reset

IMAGE_PLAYGROUND ?= ssentry-playground
PLAYGROUND_VOLUME ?= ssplay
GEOIP_DB ?= data/GeoLite2-Country.mmdb

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

# Download the free geo database (DB-IP Country Lite, no account) so geo_id is
# populated. Without it the detector runs "half" (every command geo_id 0).
# Point config.yaml `geoip_db_path` at $(GEOIP_DB) afterwards.
geo:
	./scripts/fetch-geoip.sh $(GEOIP_DB)

# Build and open the interactive playground: a clean container with the daemon
# running and a shell to drive `ssentry run` / `ssentry train` by hand. Data
# persists across runs in a named Docker volume.
playground:
	docker build -f docker/Dockerfile.playground -t $(IMAGE_PLAYGROUND) .
	docker run --rm -it -v $(PLAYGROUND_VOLUME):/app/data $(IMAGE_PLAYGROUND)

# Wipe the playground's persisted data (sessions, model, TOTP secret).
playground-reset:
	-docker volume rm $(PLAYGROUND_VOLUME)
