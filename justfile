# Just recipes for Shell Sentry (Go under ./go, Python under ./python)

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
# Point config.yaml `geoip_db_path` at the file afterwards.
geo geoip_db="data/GeoLite2-Country.mmdb":
    ./scripts/fetch-geoip.sh {{geoip_db}}

# Interactive playground: build the image, then open a shell in a clean container
# with the daemon running. Data persists in the `ssplay` Docker volume.
playground:
    docker build -f docker/Dockerfile.playground -t ssentry-playground .
    docker run --rm -it -v ssplay:/app/data ssentry-playground

# Wipe the playground's persisted data.
playground-reset:
    -docker volume rm ssplay
