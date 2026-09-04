import json
import pathlib
import unittest
import xml.etree.ElementTree as ET


ROOT = pathlib.Path(__file__).resolve().parents[2]
MAC = ROOT / "WinHUBMacAgent"


class MacAgentProductionContractTests(unittest.TestCase):
    def test_project_targets_supported_lts_native_aot(self):
        project = ET.parse(MAC / "WinHUBMacAgent.csproj").getroot()
        values = {node.tag: (node.text or "").strip() for node in project.iter()}
        self.assertEqual(values["TargetFramework"], "net10.0")
        self.assertEqual(values["RuntimeIdentifier"], "osx-arm64")
        self.assertEqual(values["PublishAot"], "true")
        self.assertEqual(values["SelfContained"], "true")

    def test_runtime_config_has_secure_macos_defaults_and_no_secrets(self):
        config = json.loads((MAC / "winhub_agent.conf.example").read_text(encoding="utf-8"))
        self.assertFalse(config["IgnoreTlsCertificateErrors"])
        self.assertTrue(config["RequireTaskSignature"])
        self.assertEqual(config["ExecutionMode"], "allowlist")
        self.assertEqual(config["AllowedActions"], ["agent_update"])
        self.assertFalse(config["AllowCrossHostUpdateDownloads"])
        self.assertNotIn("GlobalApiKey", config)
        self.assertNotIn("TaskHmacSecret", config)

    def test_release_requires_both_apple_identities_and_notarization(self):
        script = (MAC / "create-macos-agent-release.sh").read_text(encoding="utf-8")
        for required in (
            "WINHUB_CODESIGN_IDENTITY",
            "WINHUB_INSTALLER_IDENTITY",
            "WINHUB_NOTARY_PROFILE",
            "--options runtime",
            '--identifier "${label}"',
            "pkgbuild",
            "notarytool submit",
            "stapler staple",
            "spctl --assess --type install",
        ):
            self.assertIn(required, script)

    def test_installer_and_updater_pin_code_identity(self):
        installer = (MAC / "install-macos-agent.sh").read_text(encoding="utf-8")
        updater = (MAC / "update-macos-agent.sh").read_text(encoding="utf-8")
        for script in (installer, updater):
            self.assertIn("signed_identifier", script)
            self.assertIn("verify_hardened_runtime", script)
            self.assertIn("verify_launchdaemon_plist", script)
            self.assertIn('== "${label}"', script)
        self.assertIn("--expected-version", updater)
        self.assertIn("does not match installed TeamIdentifier", updater)
        self.assertIn("rollback_on_error", updater)

    def test_pkg_provisioning_is_root_only_and_removed(self):
        setup = (MAC / "setup-macos-agent.sh").read_text(encoding="utf-8")
        postinstall = (MAC / "pkg-scripts" / "postinstall").read_text(encoding="utf-8")
        self.assertIn('provisioning_dir="/private/var/tmp/${label}.provisioning"', setup)
        self.assertIn('-o root -g wheel -m 0700 "${provisioning_dir}"', setup)
        self.assertIn('-o root -g wheel -m 0600 "${runtime_config}"', setup)
        self.assertIn("valid_root_provisioning_file", postinstall)
        self.assertIn('/bin/rm -rf "${provisioning_dir}"', postinstall)

    def test_launchdaemon_and_log_rotation_contract(self):
        plist = ET.parse(MAC / "com.winhub.agent.plist").getroot()
        text = "".join(plist.itertext())
        self.assertIn("com.winhub.agent", text)
        self.assertIn(
            "/Library/PrivilegedHelperTools/com.winhub.agent/WinHUBMacAgent",
            text,
        )
        rotation = (MAC / "com.winhub.agent.newsyslog.conf").read_text(encoding="utf-8")
        self.assertIn("agent.log", rotation)
        self.assertIn("agent-error.log", rotation)
        self.assertIn("JN", rotation)
        logger = (MAC / "RotatingFileLogger.cs").read_text(encoding="utf-8")
        self.assertIn("AppendWithRotation", logger)
        self.assertIn("FileMode.Append", logger)

    def test_worker_bounds_task_output_and_passes_update_version(self):
        worker = (ROOT / "WinHUBLinuxAgent" / "Worker.cs").read_text(encoding="utf-8")
        self.assertIn("captureLimitBytes", worker)
        self.assertIn("Task output exceeded", worker)
        self.assertIn('GetPayloadString(payload, "target_version")', worker)
        self.assertIn("--expected-version", worker)
        self.assertIn('RemoveProtectedSecret("GlobalApiKey")', worker)
        self.assertIn("RequireTaskSignature=false is forbidden", worker)


if __name__ == "__main__":
    unittest.main()
