#!/bin/sh
set -eu

# Mounted fixture secrets belong to the host user and remain mode 0600. Copy
# only PostgreSQL's inputs before the official entrypoint drops privileges.
install -o postgres -g postgres -m 0600 /run/lindm-dev/server.key /var/lib/postgresql/server.key
install -o postgres -g postgres -m 0644 /run/lindm-dev/server.crt /var/lib/postgresql/server.crt
install -o postgres -g postgres -m 0600 /run/lindm-dev/postgres-password /var/lib/postgresql/bootstrap-password
install -o postgres -g postgres -m 0600 /run/lindm-dev/database-init.sql /docker-entrypoint-initdb.d/10-lindm.sql
export POSTGRES_PASSWORD_FILE=/var/lib/postgresql/bootstrap-password
exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/server.crt \
  -c ssl_key_file=/var/lib/postgresql/server.key \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c ssl_max_protocol_version=TLSv1.3
