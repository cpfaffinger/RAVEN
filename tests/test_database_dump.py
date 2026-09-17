import sys
import types
import unittest
from pathlib import Path
from unittest import mock


try:
    import fcntl  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["fcntl"] = types.ModuleType("fcntl")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backupscript"))

import backup_job  # noqa: E402


class DumpCommandTests(unittest.TestCase):
    def producers(self, call) -> list[list[str]]:
        recorded: list[list[str]] = []

        def record(cfg, producer, destination, attempts):
            recorded.append(producer)

        with mock.patch.object(backup_job, "stream_compressed", record), \
                mock.patch.object(backup_job, "remote_file_size", return_value=0):
            call()
        return recorded

    def test_schema_dump_names_the_database_positionally(self):
        producer = self.producers(
            lambda: backup_job.dump_schema({}, "shop", "/run/db/shop", 2)
        )[0]
        self.assertNotIn("--databases", producer)
        self.assertEqual(producer[-1], "shop")
        for flag in ("--routines", "--events", "--triggers", "--no-data"):
            self.assertIn(flag, producer)

    def test_data_dump_names_the_database_positionally(self):
        producer = self.producers(
            lambda: backup_job.dump_database_data({}, "shop", "/run/db/shop", 2)
        )[0]
        self.assertNotIn("--databases", producer)
        self.assertEqual(producer[-1], "shop")
        self.assertIn("--no-create-info", producer)

    def test_table_fallback_names_database_and_table(self):
        rows = [("kunden",), ("rechnungen",)]
        with mock.patch.object(backup_job, "mariadb_query", return_value=rows):
            producers = self.producers(
                lambda: backup_job.dump_database_by_table({}, "shop", "/run/db/shop", 2)
            )
        self.assertEqual(len(producers), 2)
        for producer, table in zip(producers, ("kunden", "rechnungen")):
            self.assertNotIn("--databases", producer)
            self.assertEqual(producer[-2:], ["shop", table])


if __name__ == "__main__":
    unittest.main()
