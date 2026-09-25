import json
import tempfile
import unittest
from pathlib import Path

from control_plane_lock import (
    LockError,
    OUTPUT_NAMES,
    REQUIRED_REPOSITORIES,
    SCHEMA,
    commit_for,
    load_lock,
    write_github_outputs,
)


class ControlPlaneLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "lock.json"
        self.output = self.root / "github-output.txt"

    def tearDown(self):
        self.temp.cleanup()

    def _lock(self):
        return {
            "schema": SCHEMA,
            "repositories": [
                {
                    "repository": repository,
                    "commit": f"{index + 1:040x}",
                }
                for index, repository in enumerate(REQUIRED_REPOSITORIES)
            ],
        }

    def _write(self, value):
        self.path.write_text(
            json.dumps(value, indent=2) + "\n",
            encoding="utf-8",
        )

    def test_production_lock_is_valid(self):
        lock = load_lock(Path("registry/control-plane-lock.json"))
        self.assertEqual(set(REQUIRED_REPOSITORIES), set(commit_for(lock, repo) and repo for repo in REQUIRED_REPOSITORIES))

    def test_valid_lock_passes_and_exports_all_outputs(self):
        value = self._lock()
        self._write(value)
        lock = load_lock(self.path)
        write_github_outputs(lock, self.output)
        lines = dict(
            line.split("=", 1)
            for line in self.output.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(set(OUTPUT_NAMES.values()), set(lines))
        for row in value["repositories"]:
            self.assertEqual(
                lines[OUTPUT_NAMES[row["repository"]]],
                row["commit"],
            )

    def test_unknown_root_field_fails(self):
        value = self._lock()
        value["unexpected"] = True
        self._write(value)
        with self.assertRaisesRegex(LockError, "lock root"):
            load_lock(self.path)

    def test_wrong_schema_fails(self):
        value = self._lock()
        value["schema"] = "ai-os-control-plane-lock:v2"
        self._write(value)
        with self.assertRaisesRegex(LockError, "unsupported lock schema"):
            load_lock(self.path)

    def test_missing_repository_fails(self):
        value = self._lock()
        value["repositories"].pop()
        self._write(value)
        with self.assertRaisesRegex(LockError, "repository set mismatch"):
            load_lock(self.path)

    def test_extra_repository_fails(self):
        value = self._lock()
        value["repositories"].append(
            {
                "repository": "GK-studio-JP/unexpected",
                "commit": "f" * 40,
            }
        )
        self._write(value)
        with self.assertRaisesRegex(LockError, "repository set mismatch"):
            load_lock(self.path)

    def test_duplicate_repository_fails(self):
        value = self._lock()
        value["repositories"].append(dict(value["repositories"][0]))
        self._write(value)
        with self.assertRaisesRegex(LockError, "duplicate repository"):
            load_lock(self.path)

    def test_mutable_ref_fails(self):
        value = self._lock()
        value["repositories"][0]["commit"] = "main"
        self._write(value)
        with self.assertRaisesRegex(LockError, "lowercase immutable 40-hex SHA"):
            load_lock(self.path)

    def test_uppercase_sha_fails(self):
        value = self._lock()
        value["repositories"][0]["commit"] = "A" * 40
        self._write(value)
        with self.assertRaisesRegex(LockError, "lowercase immutable 40-hex SHA"):
            load_lock(self.path)

    def test_unknown_repository_field_fails(self):
        value = self._lock()
        value["repositories"][0]["note"] = "not allowed"
        self._write(value)
        with self.assertRaisesRegex(LockError, "repository entries"):
            load_lock(self.path)

    def test_get_rejects_unmanaged_repository(self):
        value = self._lock()
        self._write(value)
        lock = load_lock(self.path)
        with self.assertRaisesRegex(LockError, "not governed"):
            commit_for(lock, "GK-studio-JP/not-managed")


if __name__ == "__main__":
    unittest.main()
