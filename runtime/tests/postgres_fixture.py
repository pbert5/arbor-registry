"""Isolate test runtimes while retaining database state across restarts."""
import os
import uuid
from unittest.mock import patch

import psycopg
from psycopg import sql


class PostgresFixture:
    def setUp(self):
        self._databases = {}
        self._admin = psycopg.connect(autocommit=True)
        self.addCleanup(self._cleanup_databases)
        super().setUp()

    def database(self, state):
        state = str(state)
        if state not in self._databases:
            name = "test_" + uuid.uuid4().hex
            self._admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
            self._databases[state] = name
        return self._databases[state]

    def _cleanup_databases(self):
        for name in self._databases.values():
            self._admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
        self._admin.close()

    def database_environment(self, state):
        return patch.dict(os.environ, PGDATABASE=self.database(state))
