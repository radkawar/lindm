#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

set -eu

# Only these database inputs cross the root-to-postgres privilege boundary.
# The serve/migrate containers never mount this volume or these credentials.
install -o postgres -g postgres -m 0600 /run/lindm/postgres.key /var/lib/postgresql/server.key
install -o postgres -g postgres -m 0644 /run/lindm/postgres.crt /var/lib/postgresql/server.crt
install -o postgres -g postgres -m 0600 /run/lindm/postgres-password /var/lib/postgresql/bootstrap-password
install -o postgres -g postgres -m 0600 /run/lindm/database-init.sql /docker-entrypoint-initdb.d/10-lindm.sql
exec /usr/local/bin/docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/server.crt \
  -c ssl_key_file=/var/lib/postgresql/server.key \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c ssl_max_protocol_version=TLSv1.3 \
  -c hba_file=/etc/postgresql/pg_hba.conf \
  -c log_statement=none \
  -c log_min_error_statement=panic
