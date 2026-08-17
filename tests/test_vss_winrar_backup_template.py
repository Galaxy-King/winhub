import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "deploy" / "import_templates" / "vss_winrar_backup"


class VssWinRarBackupTemplateTests(unittest.TestCase):
    def setUp(self):
        self.script = (TEMPLATE_DIR / "vss_winrar_backup.ps1").read_text(encoding="utf-8")
        self.report = (TEMPLATE_DIR / "vss_winrar_backup_report.jinja").read_text(encoding="utf-8")
        self.pack = json.loads((TEMPLATE_DIR / "vss_winrar_backup_pack.json").read_text(encoding="utf-8"))
        self.templates = {item["type"]: item for item in self.pack["templates"]}

    def test_pack_contains_current_source_files(self):
        self.assertEqual(self.templates["action"]["payload"]["script"], self.script)
        self.assertEqual(self.templates["report"]["payload"]["script"], self.report)

    def test_report_is_plain_text(self):
        self.assertIn("VSS WINRAR BACKUP", self.report)
        self.assertIn("CREATED ARCHIVES", self.report)
        self.assertIn("FAILED ENDPOINT DETAILS", self.report)
        self.assertNotIn("<table", self.report)
        self.assertNotIn("<div", self.report)
        self.assertNotIn("<h1", self.report)

    def test_action_uses_console_rar_executable(self):
        action_payload = self.templates["action"]["payload"]
        rar_field = action_payload["__variable_schema"]["winrar_path"]

        self.assertEqual(rar_field["default"], r"C:\Program Files\WinRAR\Rar.exe")
        self.assertIn("GetFileName($WinRarPath) -ieq 'WinRAR.exe'", self.script)
        self.assertIn("$WinRarPath = $consoleRarPath", self.script)
        self.assertIn("& $WinRarPath @winRarArguments", self.script)

    def test_single_folder_mode_archives_the_complete_tree(self):
        self.assertIn("mode = 'single-full-tree'; switch = '-r'", self.script)
        self.assertNotIn("switch = '-r-'", self.script)
        self.assertIn("contains no files eligible for", self.script)
        self.assertIn("Get-ChildItem -LiteralPath $shadowSource -File -Force -Recurse", self.script)


if __name__ == "__main__":
    unittest.main()
