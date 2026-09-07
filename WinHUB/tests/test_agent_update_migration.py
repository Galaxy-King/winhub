"""Migration contracts and adversarial archives. Never installs/stops a real service."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
import zipfile


SERVER = Path(__file__).resolve().parents[1]
REPO = SERVER.parent
ASSETS = SERVER / "deploy/agent-updaters"
ALLOW_TEST_POLICY_BYPASS = os.environ.get('WINHUB_TEST_ALLOW_POLICY_BYPASS') == '1'


def powershell_test_command():
    command = ['powershell', '-NoProfile', '-NonInteractive']
    if ALLOW_TEST_POLICY_BYPASS:
        command += ['-ExecutionPolicy', 'Bypass']
    return command


def powershell_test_environment():
    # Do not inject a parent PowerShell 7 module path into Windows PowerShell 5.1.
    return {key: value for key, value in os.environ.items() if key.upper() not in {'PSMODULEPATH', 'PSHOME'}}

spec = importlib.util.spec_from_file_location("update_migration_helpers", SERVER / "core/agent_updates.py")
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


class UpdateMigrationTests(unittest.TestCase):
    def test_signed_prepare_binds_expected_hash_for_legacy_invocation(self):
        for platform, filename in (("windows", "update-service.ps1"), ("linux", "update-linux-agent.sh")):
            script = helpers.updater_bootstrap_script(platform, "ab" * 32)
            encoded = max(re.findall(r"'([A-Za-z0-9+/=]+)'", script), key=len)
            installed = base64.b64decode(encoded).decode()
            expected = (ASSETS / filename).read_text().replace(helpers.SHA_PLACEHOLDER, "ab" * 32)
            self.assertEqual(expected, installed)
            self.assertNotIn(helpers.SHA_PLACEHOLDER, installed)
        for bad in (None, "", "a" * 63, "g" * 64, "'; exit; #"):
            with self.assertRaises(ValueError):
                helpers.updater_bootstrap_script("windows", bad)

    def test_update_dependency_requires_same_endpoint_job_and_success(self):
        task = SimpleNamespace(id="update", endpoint_id="A", job_id="job", action_type="agent_update",
                               payload=json.dumps({"__updater_prepare_task_id": "prepare"}))
        prepare = SimpleNamespace(endpoint_id="A", job_id="job", action_type="run_script", status="Pending")
        for status, expected in (("Success", "ready"), ("Pending", "wait"), ("PickedUp", "wait"),
                                 ("Running", "wait"), ("Error", "failed"), ("Cancelled", "failed")):
            prepare.status = status
            self.assertEqual(helpers.update_preparation_state(task, lambda _: prepare), expected)
        prepare.status = "Success"
        prepare.endpoint_id = "B"
        self.assertEqual(helpers.update_preparation_state(task, lambda _: prepare), "failed")
        prepare.endpoint_id, prepare.job_id = "A", "other-job"
        self.assertEqual(helpers.update_preparation_state(task, lambda _: prepare), "failed")
        self.assertEqual(helpers.update_preparation_state(task, lambda _: None), "failed")
        task.payload = '{}'
        self.assertEqual(helpers.update_preparation_state(task, lambda _: None), "ready")

    def test_publish_uses_the_same_runtime_updater_assets(self):
        for component, project, asset in (
            ("WinHUBAgentWindows", "WinHUBAgentWindows.csproj", "update-service.ps1"),
            ("WinHUBLinuxAgent", "WinHUBLinuxAgent.csproj", "update-linux-agent.sh"),
        ):
            source = (REPO / component / project).read_text(encoding='utf-8')
            self.assertIn(f'Include="../WinHUB/deploy/agent-updaters/{asset}"', source)
            self.assertIn('Include="update-protocol.json"', source)
            descriptor = json.loads((REPO / component / "update-protocol.json").read_text())
            self.assertEqual(descriptor['protocol'], 2)

    def test_preflight_precedes_service_stop_and_never_executes_old_agent(self):
        windows = (ASSETS / "update-service.ps1").read_text()
        linux = (ASSETS / "update-linux-agent.sh").read_text()
        self.assertLess(windows.index('& $candidate --check-update-server'), windows.index('Stop-Service -Name $ServiceName -ErrorAction Stop'))
        self.assertLess(linux.index('"$work/files/WinHUBLinuxAgent" --check-update-server'), linux.index('systemctl stop "$service_name"'))
        self.assertNotIn('--extract-update', windows)
        self.assertNotIn('--extract-update', linux)
        self.assertIn('Copy-WinHubCode (Join-Path $backup', windows)
        self.assertIn('backup_complete=1', linux)


class ArchiveMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="winhub-updater-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_extract(self, archive, destination):
        raise NotImplementedError

    def write_archive(self, entries):
        raise NotImplementedError

    def test_regular_archive(self):
        archive = self.write_archive([("agent.bin", b"test"), ("sub/file", b"content")])
        destination = self.root / "out"
        destination.mkdir()
        result = self.run_extract(archive, destination)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((destination / "sub/file").read_bytes(), b"content")

    def test_bad_paths_and_duplicates(self):
        for name in ("../escaped", "/absolute", "sub/../../escaped", "file:stream", "sub./file", "sub /file"):
            with self.subTest(name=name):
                destination = self.root / ("out-" + str(len(list(self.root.iterdir()))))
                destination.mkdir()
                result = self.run_extract(self.write_archive([(name, b"x")]), destination)
                self.assertNotEqual(result.returncode, 0, name)
                self.assertFalse((self.root / "escaped").exists())
        destination = self.root / 'duplicate'
        destination.mkdir()
        result = self.run_extract(self.write_archive([('same', b'a'), ('same', b'b')]), destination)
        self.assertNotEqual(result.returncode, 0)


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'Requires Windows PowerShell 5.1')
class WindowsArchiveMigrationTests(ArchiveMigrationTests):
    @classmethod
    def setUpClass(cls):
        policy = subprocess.run(powershell_test_command() + ['-Command', 'Get-ExecutionPolicy'],
                                env=powershell_test_environment(), capture_output=True, text=True, timeout=10)
        if policy.returncode or policy.stdout.strip() not in {'Bypass', 'Unrestricted', 'RemoteSigned'}:
            raise unittest.SkipTest('Windows execution policy blocks unsigned local fixtures; explicit test-process approval required')

    def write_archive(self, entries):
        archive = self.root / 'test.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            for name, content in entries:
                output.writestr(name, content)
        return archive

    def run_extract(self, archive, destination):
        # Import functions only from our checked-in script; never evaluate its service entry point.
        command = '''$ErrorActionPreference='Stop'
$ast=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$null,[ref]$null)
foreach($item in $ast.EndBlock.Statements) {
 if($item -is [Management.Automation.Language.FunctionDefinitionAst]) { Invoke-Expression $item.Extent.Text }
}
Expand-WinHubUpdate $args[1] $args[2]
'''
        runner = self.root / 'extract-test.ps1'
        runner.write_text(command)
        return subprocess.run(powershell_test_command() + ['-File', str(runner),
                               str(ASSETS / 'update-service.ps1'), str(archive), str(destination)],
                              env=powershell_test_environment(), capture_output=True, text=True, timeout=30)

    def test_zip_symlink_rejected(self):
        archive = self.root / 'link.zip'
        with zipfile.ZipFile(archive, 'w') as output:
            member = zipfile.ZipInfo('link')
            member.create_system = 3
            member.external_attr = 0o120777 << 16
            output.writestr(member, '../outside')
        destination = self.root / 'link-out'
        destination.mkdir()
        self.assertNotEqual(self.run_extract(archive, destination).returncode, 0)


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash'), 'Requires Linux/WSL')
class LinuxArchiveMigrationTests(ArchiveMigrationTests):
    def write_archive(self, entries):
        archive = self.root / 'test.tar.gz'
        with tarfile.open(archive, 'w:gz') as output:
            for name, content in entries:
                member = tarfile.TarInfo(name)
                member.size = len(content)
                output.addfile(member, io.BytesIO(content))
        return archive

    def run_extract(self, archive, destination):
        source = (ASSETS / 'update-linux-agent.sh').read_text()
        function = source.split('extract_update() {', 1)[1].split('\nassert_path()', 1)[0]
        return subprocess.run(['bash', '-c', 'set -euo pipefail\nextract_update() {' + function +
                               '\nextract_update "$1" "$2"', 'test', str(archive), str(destination)],
                              capture_output=True, text=True, timeout=30)

    def test_tar_links_and_special_files_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            archive = self.root / 'link.tar.gz'
            with tarfile.open(archive, 'w:gz') as output:
                member = tarfile.TarInfo('link')
                member.type, member.linkname = kind, '../outside'
                output.addfile(member)
            destination = self.root / str(kind)
            destination.mkdir()
            self.assertNotEqual(self.run_extract(archive, destination).returncode, 0)


@unittest.skipUnless(os.name == 'posix' and shutil.which('bash') and shutil.which('flock'), 'Requires Linux/WSL')
class LinuxUpdaterTransactionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='winhub-update-transaction-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.install = self.root / 'opt/winhub-linux-agent'
        self.data = self.root / 'var/lib/winhub-agent'
        self.units = self.root / 'etc/systemd/system'
        self.install.mkdir(parents=True)
        self.units.mkdir(parents=True)
        self.data.mkdir(parents=True)
        (self.install / 'WinHUBLinuxAgent').write_text('#!/bin/bash\necho OLD_AGENT_MUST_NOT_RUN >&2\nexit 99\n')
        (self.install / 'WinHUBLinuxAgent').chmod(0o700)
        (self.install / 'version-marker').write_text('old')
        (self.install / 'update-linux-agent.sh').write_text('# old updater\n')
        (self.install / 'winhub_agent.conf').write_text('preserve-config')
        (self.data / 'task-signing-state.json').write_text('preserve-sequence')
        (self.units / 'winhub-linux-agent.service').write_text('old unit')
        (self.root / 'running').touch()
        stub = self.root / 'bin'
        stub.mkdir()
        (stub / 'systemctl').write_text('''#!/bin/bash
set -eu
echo "$*" >> "$TEST_ROOT/service-calls"
case "$1" in
 stop) rm -f "$TEST_ROOT/running" ;;
 start)
  if [[ ${FAIL_NEW_START:-0} == 1 && $(cat "$TEST_ROOT/opt/winhub-linux-agent/version-marker") == new ]]; then exit 1; fi
  touch "$TEST_ROOT/running" ;;
 is-active) test -f "$TEST_ROOT/running" ;;
 daemon-reload) : ;;
 *) exit 95 ;;
esac
''')
        (stub / 'sleep').write_text('#!/bin/bash\nexit 0\n')
        # No chown of any real path or dependence on root for a synthetic transaction.
        (stub / 'chown').write_text('#!/bin/bash\nexit 0\n')
        for entry in stub.iterdir():
            entry.chmod(0o700)
        self.env = {**os.environ, 'PATH': str(stub) + os.pathsep + os.environ['PATH'], 'TEST_ROOT': str(self.root)}
        self.package = self.root / 'candidate.tar.gz'
        with tarfile.open(self.package, 'w:gz') as archive:
            for name, content in {
                'WinHUBLinuxAgent': '#!/bin/bash\n[[ ${FAIL_PREFLIGHT:-0} != 1 ]]\n',
                'version-marker': 'new', 'update-linux-agent.sh': '# new updater\n',
                'winhub-linux-agent.service': 'new unit',
                'winhub_agent.conf': 'must-not-overwrite-config',
                'update-protocol.json': '{"protocol":2,"platform":"linux"}',
            }.items():
                payload = content.encode()
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        self.sha = hashlib.sha256(self.package.read_bytes()).hexdigest()
        source = (ASSETS / 'update-linux-agent.sh').read_text()
        # Only sandbox paths and test UID differ. No production bypass flag exists.
        source = source.replace('/opt/winhub-linux-agent', str(self.install))
        source = source.replace('/var/lib/winhub-agent', str(self.data))
        source = source.replace('/etc/systemd/system', str(self.units))
        source = source.replace('/etc/winhub-agent', str(self.root / 'etc/winhub-agent'))
        source = source.replace('[[ $EUID == 0 ]]', '[[ $EUID == ' + str(os.geteuid()) + ' ]]')
        self.source = source

    def run_update(self, *, legacy=False, sha=None):
        runner = self.root / 'updater.sh'
        digest = sha or self.sha
        source = self.source.replace(helpers.SHA_PLACEHOLDER, digest) if legacy else self.source
        runner.write_text(source)
        command = ['bash', str(runner), '--package', str(self.package)]
        if not legacy:
            command += ['--expected-sha256', digest]
        result = subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=30)
        self.assertNotIn('OLD_AGENT_MUST_NOT_RUN', result.stdout + result.stderr)
        self.assertEqual((self.install / 'winhub_agent.conf').read_text(), 'preserve-config')
        self.assertEqual((self.data / 'task-signing-state.json').read_text(), 'preserve-sequence')
        return result

    def test_legacy_and_new_hash_contracts(self):
        result = self.run_update(legacy=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.install / 'version-marker').read_text(), 'new')
        result = self.run_update()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bad_hash_never_stops_service(self):
        result = self.run_update(sha='ab' * 32)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'service-calls').exists())
        self.assertEqual((self.install / 'version-marker').read_text(), 'old')

    def test_bad_preflight_never_stops_service(self):
        self.env['FAIL_PREFLIGHT'] = '1'
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'service-calls').exists())
        self.assertEqual((self.install / 'version-marker').read_text(), 'old')

    def test_failed_new_start_restores_old_code_and_unit(self):
        self.env['FAIL_NEW_START'] = '1'
        result = self.run_update()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.install / 'version-marker').read_text(), 'old', result.stdout + result.stderr)
        self.assertEqual((self.units / 'winhub-linux-agent.service').read_text(), 'old unit')
        self.assertTrue((self.root / 'running').exists())


# Base supplies cases, but is not itself a runnable extractor.
def load_tests(loader, tests, pattern):
    return unittest.TestSuite(loader.loadTestsFromTestCase(case) for case in
        (UpdateMigrationTests, WindowsArchiveMigrationTests, LinuxArchiveMigrationTests, LinuxUpdaterTransactionTests))
