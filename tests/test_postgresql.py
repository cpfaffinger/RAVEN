import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


try:
    import fcntl  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["fcntl"] = types.ModuleType("fcntl")
try:
    import pwd  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover - Windows test runner compatibility
    sys.modules["pwd"] = types.ModuleType("pwd")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backupscript"))

import backup_job  # noqa: E402


DOCKER = {"name": "docker_db-1", "kind": "docker", "container": "db-1", "label": "Docker-Container db-1"}
LOCAL = {"name": "local", "kind": "local", "runuser": "/usr/sbin/runuser", "label": "lokaler Cluster"}


class CommandTests(unittest.TestCase):
    def test_docker_commands_run_as_the_image_superuser(self):
        command = backup_job.postgres_command(DOCKER, "pg_dump", "--no-password")
        self.assertEqual(command[:3], ["/usr/bin/docker", "exec", "db-1"])
        self.assertIn('PGUSER="${POSTGRES_USER:-postgres}"', command[5])
        self.assertEqual(command[6:], ["pg_dump", "--no-password"])

    def test_local_commands_run_as_postgres(self):
        self.assertEqual(
            backup_job.postgres_command(LOCAL, "psql", "-c", "select 1"),
            ["/usr/sbin/runuser", "-u", "postgres", "--", "psql", "-c", "select 1"],
        )

    def test_database_names_cannot_become_connection_parameters(self):
        self.assertEqual(backup_job.postgres_conninfo("shop"), "dbname='shop'")
        self.assertEqual(
            backup_job.postgres_conninfo("x' host=evil"), "dbname='x\\' host=evil'"
        )


class DataDirectoryTests(unittest.TestCase):
    def test_container_path_maps_to_the_longest_bind_mount(self):
        mounts = "/home/postgres\t/srv/other\n/home/postgres/pgdata\t/etc/compose/data/postgres\n"
        result = subprocess.CompletedProcess([], 0, stdout=mounts, stderr="")
        with mock.patch.object(backup_job, "run", return_value=result):
            self.assertEqual(
                backup_job.docker_host_path("db-1", "/home/postgres/pgdata/data"),
                str(Path("/etc/compose/data/postgres") / "data"),
            )

    def test_unmounted_container_path_has_no_host_path(self):
        result = subprocess.CompletedProcess([], 0, stdout="/var/log\t/srv/log\n", stderr="")
        with mock.patch.object(backup_job, "run", return_value=result):
            self.assertIsNone(backup_job.docker_host_path("db-1", "/var/lib/postgresql/data"))

    def test_only_paths_below_a_source_are_excluded(self):
        excluded = ["/etc/compose/db/data", "/var/lib/postgresql/17/main", "/etc"]
        self.assertEqual(backup_job.excluded_below("/etc", excluded), ["compose/db/data"])
        self.assertEqual(backup_job.excluded_below("/home", excluded), [])

    def test_data_directories_stay_when_databases_are_not_dumped(self):
        instances = [dict(DOCKER, data_directory="/etc/compose/db/data")]
        enabled = {"backup": {"postgresql_databases_enabled": True}}
        disabled = {"backup": {"postgresql_databases_enabled": False, "postgresql_roles_enabled": True}}
        self.assertEqual(backup_job.dumped_data_directories(enabled, instances), ["/etc/compose/db/data"])
        self.assertEqual(backup_job.dumped_data_directories(disabled, instances), [])


class BackupTests(unittest.TestCase):
    def test_every_database_and_the_globals_land_per_instance(self):
        recorded: list[tuple[list[str], str]] = []

        def record(cfg, producer, destination, attempts, **kwargs):
            recorded.append((producer, destination))

        cfg = {"backup": {"postgresql_databases_enabled": True, "postgresql_roles_enabled": True}}
        with mock.patch.object(backup_job, "stream_compressed", record), \
                mock.patch.object(backup_job, "remote_file_size", return_value=10), \
                mock.patch.object(backup_job, "postgres_database_inventory",
                                  return_value=(["app", "postgres"], {"app": 100, "postgres": 5})):
            report = backup_job.backup_postgresql(cfg, "/run", [dict(DOCKER, version="17")])
        destinations = [destination for _producer, destination in recorded]
        self.assertEqual(destinations, [
            "/run/postgresql/docker_db-1/globals.sql.zst",
            "/run/postgresql/docker_db-1/databases/app.sql.zst",
            "/run/postgresql/docker_db-1/databases/postgres.sql.zst",
        ])
        self.assertIn("--globals-only", recorded[0][0])
        self.assertIn("--dbname=dbname='app'", recorded[1][0])
        self.assertEqual(report["database_count"], 2)
        self.assertEqual(report["estimated_bytes"], 105)
        self.assertEqual(report["compressed_bytes"], 30)

    def test_disabled_policy_dumps_nothing(self):
        cfg = {"backup": {"postgresql_databases_enabled": False, "postgresql_roles_enabled": False}}
        with mock.patch.object(backup_job, "stream_compressed") as stream:
            report = backup_job.backup_postgresql(cfg, "/run", [DOCKER])
        stream.assert_not_called()
        self.assertEqual(report["database_count"], 0)

    def test_policy_snapshot_switches_postgresql(self):
        cfg = {"backup": {"mariadb_available": False}}
        backup_job.apply_command_policy(cfg, {"policy": {
            "id": 1, "name": "Standard", "paths": [],
            "postgresql_databases_enabled": True, "postgresql_roles_enabled": False,
        }})
        self.assertTrue(cfg["backup"]["postgresql_databases_enabled"])
        self.assertFalse(cfg["backup"]["postgresql_roles_enabled"])


TAR = shutil.which("tar")


@unittest.skipUnless(TAR, "tar is required")
class TarExcludeTests(unittest.TestCase):
    def test_anchored_exclude_drops_exactly_the_data_directory(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root) / "etc"
            (base / "compose" / "db" / "data").mkdir(parents=True)
            (base / "compose" / "db" / "data" / "PG_VERSION").write_text("17")
            (base / "compose" / "db" / "init.sql").write_text("--")
            (base / "data").mkdir()
            (base / "data" / "keep").write_text("x")
            listing = subprocess.run(
                [TAR, "--anchored", "--no-wildcards", "--exclude=etc/compose/db/data",
                 "-C", root, "-cf", "-", "etc"],
                capture_output=True, check=True,
            )
            names = subprocess.run(
                [TAR, "-tf", "-"], input=listing.stdout, capture_output=True, check=True
            ).stdout.decode().split()
        self.assertIn("etc/compose/db/init.sql", names)
        self.assertIn("etc/data/keep", names)
        self.assertFalse(any(name.startswith("etc/compose/db/data") for name in names))


if __name__ == "__main__":
    unittest.main()
