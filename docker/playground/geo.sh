#!/bin/bash
# Download the free geo database into the playground so geo_id gets populated.
# Without it every command scores geo_id 0 ("country unknown") and the geo
# signal is dead. config.yaml already points geoip_db_path here, so ssentry
# picks it up on the next `ssentry run`.
exec /usr/local/bin/fetch-geoip /app/data/GeoLite2-Country.mmdb
