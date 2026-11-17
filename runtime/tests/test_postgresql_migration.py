import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

import psycopg

from arbor_registry_runtime import FileProvider, Runtime


class PostgreSQLMigrationTests(unittest.TestCase):
    def test_sqlite_import_is_ordered_and_only_runs_once(self):
        schema = 'migration_' + uuid.uuid4().hex
        with psycopg.connect(autocommit=True) as admin:
            admin.execute(f'CREATE SCHEMA {schema}')
            old_options = os.environ.get('PGOPTIONS')
            os.environ['PGOPTIONS'] = f'-c search_path={schema}'
            try:
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    state = root / 'state'
                    state.mkdir(mode=0o700)
                    with sqlite3.connect(state / 'registry.sqlite3') as legacy:
                        legacy.executescript('''
                            CREATE TABLE records (record_key TEXT PRIMARY KEY, record_id TEXT, generation INTEGER, predecessor TEXT, status TEXT NOT NULL, reason TEXT, envelope TEXT NOT NULL);
                            CREATE TABLE projection (record_id TEXT PRIMARY KEY, schema TEXT NOT NULL, payload TEXT NOT NULL, generation INTEGER NOT NULL);
                            CREATE TABLE local_genesis (identity TEXT PRIMARY KEY, domain TEXT NOT NULL, public_key TEXT NOT NULL, record_digest TEXT NOT NULL);
                            CREATE TABLE provider_cursors (stream TEXT PRIMARY KEY, cursor TEXT NOT NULL);
                            INSERT INTO records VALUES ('a', 'a', 1, NULL, 'quarantined', 'bad', '{}');
                            INSERT INTO records VALUES ('b', 'b', 1, NULL, 'quarantined', 'bad', '{}');
                            INSERT INTO records VALUES ('c', 'c', 'invalid', NULL, 'quarantined', 'bad', '{"generation":"invalid"}');
                            INSERT INTO projection VALUES ('a', 'node-identity', '{}', 1);
                            INSERT INTO local_genesis VALUES ('node', 'example', 'key', 'digest');
                            INSERT INTO provider_cursors VALUES ('default', '7');
                        ''')
                    (state / 'registry.sqlite3').chmod(0o600)
                    provider = FileProvider(root / 'history')
                    runtime = Runtime(state, provider, {})
                    self.assertEqual([r[0] for r in runtime.db.execute('SELECT record_key FROM records ORDER BY rowid')], ['a', 'b', 'c'])
                    self.assertEqual(runtime.projection()['a']['generation'], 1)
                    self.assertEqual(runtime._provider_cursor(), 7)
                    self.assertEqual(admin.execute(f"SELECT count(*) FROM {schema}.records").fetchone()[0], 3)
                    self.assertEqual(runtime.local_authorities['node'], ('example', 'key'))
                    runtime.db.execute("DELETE FROM records WHERE record_key = 'a'")
                    runtime.db.commit()
                    runtime.close()
                    runtime = Runtime(state, provider, {})
                    self.assertEqual([r[0] for r in runtime.db.execute('SELECT record_key FROM records ORDER BY rowid')], ['b', 'c'])
                    runtime.close()
            finally:
                if old_options is None:
                    os.environ.pop('PGOPTIONS', None)
                else:
                    os.environ['PGOPTIONS'] = old_options
                admin.execute(f'DROP SCHEMA {schema} CASCADE')
