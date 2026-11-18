#!/usr/bin/env python3
"""Initialize the configured database or upgrade an existing SQLite schema."""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from sqlalchemy import inspect

from app import create_app
from app.extensions import db

DNS_KEYS = {'domain': ('zone_id',), 'dns_record': ('record_id',)}
TABLES = ('api_token', 'domain', 'dns_record')
LEGACY_DEFAULTS = {
    'provider_type': "'cloudflare'",
    'sort_order': '0',
    'dns_sync_version': '0',
    'encrypted_credentials': 'NULL',
    'encrypted_token': 'NULL',
    'priority': 'NULL',
}


def backup_database(database):
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = database.with_name(f'{database.stem}.backup-{stamp}.db')
    with TemporaryDirectory(dir=database.parent) as temporary:
        path = Path(temporary) / 'backup.db'
        path.touch(mode=0o600)
        with closing(sqlite3.connect(f'{database.as_uri()}?mode=ro', uri=True)) as source:
            with closing(sqlite3.connect(path)) as destination:
                source.backup(destination)
        path.replace(backup)
    print(f'已备份数据库 {backup}')


def tables_to_rebuild(connection):
    inspector = inspect(connection)
    existing = {}
    rebuild = []
    for name in TABLES:
        if not inspector.has_table(name):
            continue
        columns = {column['name']: column for column in inspector.get_columns(name)}
        existing[name] = set(columns)
        unique_keys = {tuple(key['column_names']) for key in inspector.get_unique_constraints(name)}
        missing_columns = set(db.metadata.tables[name].columns.keys()) - set(columns)
        legacy_token = name == 'api_token' and not columns.get('encrypted_token', {}).get('nullable', True)
        if rebuild or missing_columns or legacy_token or DNS_KEYS.get(name) in unique_keys:
            rebuild.append(name)
    return rebuild, existing


def migrate():
    app = create_app()
    with app.app_context(), db.engine.begin() as connection:
        sqlite = connection.dialect.name == 'sqlite'
        if sqlite:
            connection.exec_driver_sql('BEGIN IMMEDIATE')
        rebuild, existing = tables_to_rebuild(connection)
        if rebuild and not sqlite:
            raise RuntimeError('旧版表结构的自动迁移仅支持 SQLite。')

        if rebuild:
            # Reserve the write lock before taking a consistent backup and changing tables.
            database = connection.exec_driver_sql('PRAGMA database_list').first()[2]
            if database:
                backup_database(Path(database))
            for name in reversed(rebuild):
                connection.exec_driver_sql(f'ALTER TABLE {name} RENAME TO legacy_{name}')

        db.metadata.create_all(connection)
        for name in rebuild:
            columns = db.metadata.tables[name].columns.keys()
            values = [column if column in existing[name] else LEGACY_DEFAULTS[column] for column in columns]
            connection.exec_driver_sql(
                f"INSERT INTO {name} ({', '.join(columns)}) "
                f"SELECT {', '.join(values)} FROM legacy_{name}"
            )
        for name in reversed(rebuild):
            connection.exec_driver_sql(f'DROP TABLE legacy_{name}')
        if rebuild and connection.exec_driver_sql('PRAGMA foreign_key_check').first():
            raise RuntimeError('外键检查失败，已取消数据库迁移。')


if __name__ == '__main__':
    migrate()
