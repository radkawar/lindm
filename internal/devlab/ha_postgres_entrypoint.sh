#!/bin/sh
# SPDX-License-Identifier: Apache-2.0

# HA laboratory PostgreSQL node. Runs as root only to install mounted inputs,
# then drops to the image's postgres account. LINDM_HA_ROLE selects the initial
# primary (synchronous commit to the named standby) or a standby cloned from it
# over verify-full TLS. Never used outside the disposable lab topology.
set -eu

install -o postgres -g postgres -m 0600 /run/lindm-ha/server.key /var/lib/postgresql/server.key
install -o postgres -g postgres -m 0644 /run/lindm-ha/server.crt /var/lib/postgresql/server.crt
install -o postgres -g postgres -m 0644 /run/lindm-ha/transport-ca.crt /var/lib/postgresql/transport-ca.crt

set -- \
  -c listen_addresses=127.0.0.1 \
  -c ssl=on \
  -c ssl_cert_file=/var/lib/postgresql/server.crt \
  -c ssl_key_file=/var/lib/postgresql/server.key \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c ssl_max_protocol_version=TLSv1.3 \
  -c wal_level=replica \
  -c max_wal_senders=4 \
  -c hot_standby=on \
  -c synchronous_commit=on \
  -c tcp_keepalives_idle=10 \
  -c tcp_keepalives_interval=5 \
  -c tcp_keepalives_count=3

case "${LINDM_HA_ROLE:-}" in
primary)
  install -o postgres -g postgres -m 0600 /run/lindm-ha/postgres-password /var/lib/postgresql/bootstrap-password
  install -o postgres -g postgres -m 0600 /run/lindm-ha/database-init.sql /docker-entrypoint-initdb.d/10-lindm.sql
  export POSTGRES_PASSWORD_FILE=/var/lib/postgresql/bootstrap-password
  # database-init.sql persists synchronous_standby_names with ALTER SYSTEM, so
  # the image's temporary initialization server never waits for a standby.
  exec /usr/local/bin/docker-entrypoint.sh postgres "$@"
  ;;
standby)
  install -o postgres -g postgres -m 0600 /run/lindm-ha/replication.pgpass /var/lib/postgresql/replication.pgpass
  conninfo="host=localhost port=${LINDM_HA_PRIMARY_PORT:?} user=lindm_replicator passfile=/var/lib/postgresql/replication.pgpass sslmode=verify-full sslrootcert=/var/lib/postgresql/transport-ca.crt application_name=lindm_standby"
  if [ ! -s "$PGDATA/PG_VERSION" ]; then
    mkdir -p "$PGDATA"
    chown -R postgres:postgres /var/lib/postgresql
    chmod 0700 "$PGDATA"
    gosu postgres pg_basebackup --pgdata="$PGDATA" --wal-method=stream --checkpoint=fast --dbname="$conninfo"
    gosu postgres touch "$PGDATA/standby.signal"
    # The clone inherits the primary's ALTER SYSTEM settings. After promotion
    # it has no standby of its own, so it must not wait for one.
    printf "primary_conninfo = '%s'\nsynchronous_standby_names = ''\n" "$conninfo" | gosu postgres tee -a "$PGDATA/postgresql.auto.conf" >/dev/null
  fi
  exec gosu postgres postgres "$@"
  ;;
*)
  echo "LINDM_HA_ROLE must be primary or standby" >&2
  exit 64
  ;;
esac
