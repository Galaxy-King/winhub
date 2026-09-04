"""Exercise the actual release/copy scripts without touching installed services."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


SERVER = Path(__file__).resolve().parents[1]
HAS_UNIX_TOOLS = os.name == "posix" and all(shutil.which(name) for name in ("bash", "tar", "rsync"))


@unittest.skipUnless(HAS_UNIX_TOOLS, "Requires Linux/WSL with Bash, GNU tar and rsync")
class ServerDistributionTests(unittest.TestCase):
    def setUp(self):
        self.workspace = tempfile.TemporaryDirectory(prefix="winhub-distribution-")
        self.addCleanup(self.workspace.cleanup)
        self.root = Path(self.workspace.name)
        self.source = self.root / "checkout" / "WinHUB"
        for entry in (SERVER / "deploy/server-files.txt").read_text().splitlines():
            path = self.source / entry
            if entry.endswith("/"):
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture\n")
        (self.source / "VERSION").write_text("1.2.3\n")
        (self.source / "deploy/debian").mkdir()
        for entry in ("deploy/server-files.txt", "deploy/server-excludes.txt", "deploy/create_release.sh",
                      "deploy/debian/sync_server_files.sh"):
            shutil.copy2(SERVER / entry, self.source / entry)
        for entry in (".git/config", ".env", "data/secret.db", "core/__pycache__/test.pyc",
                      "modules/test/.env", "modules/test/data/private.json", "modules/test/test.key",
                      "deploy/forgotten.zip", "tests/test_private.py", "WinHUB-WiKi/README.md"):
            path = self.source / entry
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("MUST NOT SHIP\n")
        (self.source / "core/app.py").write_text("# server source\n")
        (self.source / "modules/test/feature.py").write_text("# module source\n")
        (self.source / "deploy/debian/winhub.env.example").write_text("SECRET_KEY=replace-with-secret\n")

    def run_bash(self, command, *args, **kwargs):
        return subprocess.run(["bash", "-c", command, "test", *map(str, args)],
                              text=True, capture_output=True, check=True, **kwargs)

    def test_release_excludes_runtime_secrets_agents_and_caches(self):
        self.run_bash('bash "$1"', self.source / "deploy/create_release.sh")
        archive_path = self.source / "dist/winhub-v1.2.3.tar.gz"
        with tarfile.open(archive_path) as archive:
            names = {item.name for item in archive.getmembers() if item.isfile()}
            for item in archive.getmembers():
                if item.isfile():
                    self.assertNotIn(b"MUST NOT SHIP", archive.extractfile(item).read(), item.name)
        self.assertIn("core/app.py", names)
        self.assertIn("modules/test/feature.py", names)
        self.assertIn("deploy/debian/winhub.env.example", names)
        self.assertIn("deploy/server-files.txt", names)
        manifest = json.loads((archive_path.parent / "winhub-v1.2.3.manifest.json").read_text())
        self.assertEqual(manifest["server_archive_sha256"], hashlib.sha256(archive_path.read_bytes()).hexdigest())

    def test_install_copy_accepts_monorepo_and_preserves_existing_runtime(self):
        target = self.root / "installed"
        for entry in ("data/keep.db", "venv/keep", ".env", "core/old_module.py"):
            path = target / entry
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("existing\n")
        self.run_bash('source "$1"; winhub_sync_server_files "$2" "$3"',
                      self.source / "deploy/debian/sync_server_files.sh", self.source.parent, target)
        self.assertTrue((target / "core/app.py").is_file())
        self.assertFalse((target / "core/old_module.py").exists())
        self.assertFalse((target / "modules/test/.env").exists())
        self.assertFalse((target / "modules/test/data").exists())
        for entry in ("data/keep.db", "venv/keep", ".env"):
            self.assertEqual((target / entry).read_text(), "existing\n")
        for entry in (".git", "WinHUB-WiKi", "tests", "core/__pycache__", "deploy/forgotten.zip"):
            self.assertFalse((target / entry).exists(), entry)

    def test_fresh_secrets_are_independent_and_resuming_keeps_them(self):
        installer = (SERVER / "deploy/debian/install_debian.sh").read_text()
        function = installer.split("generate_env_secrets() {", 1)[1].split("\ndetect_public_host()", 1)[0]
        command = 'ENV_FILE="$1"\ngenerate_env_secrets() {' + function + "\ngenerate_env_secrets"
        env_file = self.root / "winhub.env"
        shutil.copy2(SERVER / "deploy/debian/winhub.env.example", env_file)
        self.run_bash(command, env_file)
        values = dict(line.split("=", 1) for line in env_file.read_text().splitlines()
                      if line and not line.startswith("#") and "=" in line)
        keys = ("SECRET_KEY", "AGENT_API_KEY", "AGENT_TASK_HMAC_SECRET", "HISTORY_SEARCH_KEY", "POSTGRES_PASSWORD")
        self.assertEqual(len({values[key] for key in keys}), len(keys))
        for key in keys:
            self.assertGreaterEqual(len(values[key]), 64)
            self.assertNotIn("replace-with", values[key])
        original = env_file.read_bytes()
        self.run_bash(command, env_file)
        self.assertEqual(original, env_file.read_bytes())

    def test_update_keeps_history_key_compatibility(self):
        updater = (SERVER / "deploy/debian/update_winhub.sh").read_text()
        function = updater.split("sync_env_file() {", 1)[1].split("\nenv_get()", 1)[0]
        command = 'APP_DIR="$1"\nENV_FILE="$2"\nsync_env_file() {' + function + "\nsync_env_file"
        env_file = self.root / "existing.env"
        env_file.write_text("AGENT_TASK_HMAC_SECRET=existing-task-key\n")
        self.run_bash(command, SERVER, env_file)
        values = dict(line.split("=", 1) for line in env_file.read_text().splitlines()
                      if line and not line.startswith("#") and "=" in line)
        self.assertEqual(values["HISTORY_SEARCH_KEY"], "")
        self.assertEqual(values["AGENT_TASK_HMAC_SECRET"], "existing-task-key")
        env_file.write_text("HISTORY_SEARCH_KEY=existing-dedicated-key\n")
        self.run_bash(command, SERVER, env_file)
        self.assertIn("HISTORY_SEARCH_KEY=existing-dedicated-key\n", env_file.read_text())


if __name__ == "__main__":
    unittest.main()
