#!/bin/sh
# Download the free DB-IP Country Lite database (MaxMind mmdb format, no account
# or licence key needed) to $1 (default ./data/GeoLite2-Country.mmdb).
#
# This is what fills geo_id in the feature vector. Without it every command
# scores geo_id 0 ("country unknown") and the geo signal is effectively dead,
# so the detector runs "half". Point config.yaml `geoip_db_path` at the
# downloaded file to switch it on.
#
# ponytail: DB-IP Country Lite over MaxMind GeoLite2 so this needs no account.
# It is the same mmdb format geoip2-golang reads; swap the URL for MaxMind's
# licensed download if you need their data specifically.
set -eu

DEST="${1:-data/GeoLite2-Country.mmdb}"
mkdir -p "$(dirname "$DEST")"

# Early in a new month the current file may not be published yet, so fall back
# to the previous month. GNU date uses -d; BSD/macOS date uses -v.
THIS="$(date +%Y-%m)"
PREV="$(date -d 'last month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m)"

for M in "$THIS" "$PREV"; do
    URL="https://download.db-ip.com/free/dbip-country-lite-${M}.mmdb.gz"
    echo "fetching $URL"
    if curl -fSL "$URL" -o "$DEST.gz"; then
        gunzip -f "$DEST.gz"
        echo "geoip db ready -> $DEST"
        exit 0
    fi
done

echo "failed to download geoip db (checked $THIS and $PREV)" >&2
exit 1
