import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "portal"))

from runtime_config import effective_settings, runtime_config  # noqa: E402


class RuntimeConfigTests(unittest.TestCase):
    def config(self, database: Path) -> dict:
        return {
            "domain": {"tld": "example.com", "subdomain": "backup"},
            "server": {"port": 49180},
            "database": {"path": str(database)},
            "onboarding": {
                "username_prefix": "backup_",
                "backup_ssh_port": 49150,
                "remote_hostname": "backup",
                "deployment_token_minutes": 15,
                "default_schedule_hour": 2,
                "default_schedule_minute": 0,
                "default_interval_hours": 24,
                "min_remote_free_bytes": 1024,
                "database_split_threshold_bytes": 512,
            },
        }

    def test_bootstrap_fallback_without_database(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config(Path(directory) / "missing.db")
            self.assertEqual(runtime_config(config)["domain"]["subdomain"], "backup")
            self.assertEqual(effective_settings(config)["backup_ssh_port"], 49150)

    def test_database_values_and_pending_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "portal.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE portal_settings (id INTEGER PRIMARY KEY,domain_tld TEXT,domain_subdomain TEXT,"
                "pending_domain_tld TEXT,pending_domain_subdomain TEXT,domain_change_pending INTEGER,"
                "username_prefix TEXT,backup_ssh_port INTEGER,remote_hostname TEXT,"
                "deployment_token_minutes INTEGER,default_schedule_hour INTEGER,default_schedule_minute INTEGER,"
                "default_interval_hours INTEGER,"
                "min_remote_free_bytes INTEGER,database_split_threshold_bytes INTEGER)"
            )
            connection.execute(
                "INSERT INTO portal_settings VALUES(1,'example.net','raven','example.org','next',1,"
                "'raven_',49222,'archive',30,3,15,12,2048,1024)"
            )
            connection.commit()
            connection.close()
            config = self.config(database)
            active = runtime_config(config)
            pending = runtime_config(config, prefer_pending_domain=True)
            self.assertEqual(active["domain"], {"tld": "example.net", "subdomain": "raven"})
            self.assertEqual(pending["domain"], {"tld": "example.org", "subdomain": "next"})
            self.assertEqual(pending["onboarding"]["backup_ssh_port"], 49222)


if __name__ == "__main__":
    unittest.main()
