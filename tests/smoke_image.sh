#!/usr/bin/env bash
set -euo pipefail

image=$1
workdir=$(mktemp -d)
container=
cleanup() {
    if [[ -n "$container" ]]; then
        docker rm -f "$container" >/dev/null
    fi
}
trap cleanup EXIT

docker run --rm --entrypoint python -v "$PWD/tests:/app/tests:ro" "$image" \
    -m unittest discover -s tests -v

key=$(docker run --rm --entrypoint python "$image" -c \
    'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')

for case in fresh legacy; do
    data="$workdir/$case"
    mkdir "$data"
    if [[ "$case" == legacy ]]; then
        python3 - "$data/smoke.db" <<'PY'
import sqlite3
import sys
from pathlib import Path

with sqlite3.connect(sys.argv[1]) as database:
    database.executescript(Path('tests/fixtures/legacy.sql').read_text())
PY
    fi

    container=$(docker run --detach --health-interval=1s --health-retries=10 \
        -e ENCRYPTION_KEY="$key" -e SECRET_KEY=ci-smoke-test-only \
        -e DATABASE_URL=sqlite:////app/data/smoke.db -v "$data:/app/data" "$image")
    for attempt in {1..45}; do
        status=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$container")
        if [[ "$status" == 'running healthy' || "$status" == 'running unhealthy' || "$status" == exited* ]]; then
            break
        fi
        sleep 1
    done
    if [[ "$status" != 'running healthy' ]]; then
        docker logs "$container"
        exit 1
    fi

    docker exec -i "$container" python - "$case" <<'PY'
import sqlite3
import sys
from pathlib import Path

with sqlite3.connect('file:/app/data/smoke.db?mode=ro', uri=True) as database:
    assert database.execute('SELECT count(*) FROM dns_record').fetchone()[0] == (sys.argv[1] == 'legacy')
    assert database.execute('SELECT dns_sync_version FROM domain').fetchall() == (
        [(0,)] if sys.argv[1] == 'legacy' else []
    )
    assert database.execute('PRAGMA foreign_key_check').fetchall() == []

assert len(list(Path('/app/data').glob('smoke.backup-*.db'))) == (sys.argv[1] == 'legacy')
PY
    cleanup
    container=
done
