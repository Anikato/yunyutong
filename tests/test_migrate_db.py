import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
LEGACY_SCHEMA = ROOT / 'tests' / 'fixtures' / 'legacy.sql'


class MigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        # Keep the old script's hard-coded database path inside this directory too.
        self.script = root / 'migrate_db.py'
        shutil.copyfile(ROOT / 'migrate_db.py', self.script)
        data = root / 'data'
        data.mkdir()
        self.database = data / 'dns.db'

    def migrate(self, database_url=None, module_path=ROOT, expect_success=True):
        result = subprocess.run(
            [sys.executable, str(self.script)],
            cwd=self.script.parent,
            env={
                **os.environ,
                'PYTHONPATH': str(module_path),
                'DATABASE_URL': database_url or f'sqlite:///{self.database}',
                'ENCRYPTION_KEY': Fernet.generate_key().decode(),
            },
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode == 0, expect_success, result.stdout + result.stderr)

    def test_creates_tables_in_configured_empty_database(self):
        self.migrate()
        self.assertTrue(self.database.is_file())
        with closing(sqlite3.connect(self.database)) as connection:
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
            self.assertEqual({name for name, in tables}, {'user', 'api_token', 'domain', 'dns_record'})
        self.assertEqual(list(self.database.parent.glob('*.backup-*.db')), [])

    def test_resolves_relative_sqlite_urls_like_the_web_application(self):
        project = self.script.parent
        shutil.copytree(ROOT / 'app', project / 'app', ignore=shutil.ignore_patterns('__pycache__'))
        shutil.copyfile(ROOT / 'config.py', project / 'config.py')
        self.migrate(database_url='sqlite:///relative.db', module_path=project)
        self.assertTrue((project / 'instance' / 'relative.db').is_file())
        self.assertFalse((project / 'relative.db').exists())

    def test_preserves_legacy_rows_and_replaces_global_uniqueness_once(self):
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(LEGACY_SCHEMA.read_text())
        self.migrate()
        self.migrate()

        with closing(sqlite3.connect(self.database)) as connection:
            token = connection.execute(
                'SELECT provider_type, encrypted_token, encrypted_credentials, sort_order FROM api_token WHERE id=10'
            ).fetchone()
            self.assertEqual(token, ('cloudflare', b'\x12\x34', None, 0))
            record = connection.execute('SELECT content, domain_id, priority FROM dns_record WHERE id=30').fetchone()
            self.assertEqual(record, ('192.0.2.1', 20, None))
            connection.execute(
                "INSERT INTO api_token (name, provider_type, encrypted_credentials, status, user_id, sort_order) "
                "VALUES ('new', 'aliyun', X'12', 'valid', 1, 0)"
            )
            connection.execute(
                "INSERT INTO domain (id, zone_id, name, api_token_id, sort_order) "
                "VALUES (21, 'example.test', 'example.test', 11, 0)"
            )
            connection.execute(
                "INSERT INTO dns_record (record_id, type, name, content, domain_id) "
                "VALUES ('remote-record', 'A', 'www.example.test', '192.0.2.2', 21)"
            )
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute(
                    "INSERT INTO domain (zone_id, name, api_token_id, sort_order) "
                    "VALUES ('example.test', 'example.test', 10, 0)"
                )
            self.assertEqual(connection.execute('PRAGMA foreign_key_check').fetchall(), [])

        backups = list(self.database.parent.glob('*.backup-*.db'))
        self.assertEqual(len(backups), 1)
        with closing(sqlite3.connect(backups[0])) as backup:
            self.assertEqual(backup.execute('SELECT id FROM dns_record').fetchone(), (30,))
            self.assertNotIn('priority', [column[1] for column in backup.execute('PRAGMA table_info(dns_record)')])

    def test_failed_migration_leaves_original_schema_and_data_in_place(self):
        with closing(sqlite3.connect(self.database)) as connection:
            connection.executescript(LEGACY_SCHEMA.read_text())
            connection.execute('UPDATE dns_record SET domain_id = 999')
            connection.commit()

        self.migrate(expect_success=False)

        with closing(sqlite3.connect(self.database)) as connection:
            self.assertEqual(connection.execute('SELECT id, domain_id FROM dns_record').fetchone(), (30, 999))
            self.assertNotIn('priority', [column[1] for column in connection.execute('PRAGMA table_info(dns_record)')])
            self.assertIsNone(connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'legacy_dns_record'"
            ).fetchone())


if __name__ == '__main__':
    unittest.main()
