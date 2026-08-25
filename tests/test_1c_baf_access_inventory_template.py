import json
import unittest
from pathlib import Path

from core.report_renderer import render_report, validate_report_template


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_DIR = ROOT / "deploy" / "import_templates" / "1c_baf_access_inventory"


def result(host, ip, installed):
    octets = [int(part) for part in ip.split(".")] if ip else [999, 999, 999, 999]
    key = ".".join(f"{part:03d}" for part in octets) + f"|{host.lower()}"
    return {
        "host": host,
        "status": "Success",
        "log": "Structured JSON result",
        "data": {
            "computer_name": host,
            "checked_at_utc": "2026-08-21T12:00:00Z",
            "primary_ip": ip,
            "ipv4_192_168": [ip] if ip else [],
            "ip_sort_key": key,
            "software_installed": installed,
            "software": [
                {
                    "kind": "Installed program",
                    "name": "1C:Enterprise 8",
                    "version": "8.3.25",
                    "path": r"C:\Program Files\1cv8",
                    "state": "Installed",
                }
            ]
            if installed
            else [],
            "active_access_accounts": [
                {
                    "name": r"DOMAIN\operator",
                    "sid": "S-1-5-21-1",
                    "enabled": True,
                    "locked_out": False,
                    "status_verified": True,
                    "status_source": "WinNT ADSI",
                    "granted_by": ["Remote Desktop Users"],
                }
            ]
            if installed
            else [],
            "access_summary": {
                "discovered_users": 1 if installed else 0,
                "active_enabled_unlocked": 1 if installed else 0,
                "disabled": 0,
                "locked_out": 0,
                "unverified": 0,
            },
            "access_definition": "Windows interactive access",
            "warnings": [],
        },
    }


class OneCBafAccessInventoryTemplateTests(unittest.TestCase):
    def setUp(self):
        self.script = (TEMPLATE_DIR / "1c_baf_access_inventory.ps1").read_text(encoding="utf-8")
        self.report = (TEMPLATE_DIR / "1c_baf_access_inventory_report.jinja").read_text(encoding="utf-8")
        self.pack = json.loads(
            (TEMPLATE_DIR / "1c_baf_access_inventory_pack.json").read_text(encoding="utf-8")
        )
        self.templates = {item["type"]: item for item in self.pack["templates"]}

    def test_pack_contains_current_source_files_and_report_link(self):
        self.assertEqual(self.templates["action"]["payload"]["script"], self.script)
        self.assertEqual(self.templates["report"]["payload"]["script"], self.report)
        self.assertEqual(
            self.templates["action"]["payload"]["__report_template_id"],
            self.templates["report"]["id"],
        )
        self.assertEqual(self.templates["action"]["payload"]["__variable_schema"], {})

    def test_action_has_expected_inventory_sources(self):
        for marker in (
            "Win32_NetworkAdapterConfiguration",
            "Get-NetIPAddress",
            "Win32_Service",
            "CurrentVersion\\Uninstall",
            "1cv8.exe",
            r"business\s+automation\s+framework",
            "S-1-5-32-544",
            "S-1-5-32-555",
            "Win32_UserAccount",
            "localStates.accounts",
            "Expand-WinHubAccessMember",
            "$_.status_verified -and $_.enabled -and -not $_.locked_out",
        ):
            self.assertIn(marker, self.script)

        self.assertNotIn("quser.exe", self.script)

    def test_report_is_valid_and_sorts_installed_servers_numerically_by_ip(self):
        validate_report_template(self.report)
        self.assertNotIn("|sort", self.report)
        output = render_report(
            self.report,
            {
                "job_title": "Inventory",
                "results": [
                    result("server-10", "192.168.10.2", True),
                    result("server-2", "192.168.2.20", True),
                    result("server-3", "192.168.3.5", False),
                ],
                "ignored_results": [],
            },
        )

        installed_section = output.split("1С / BAF — НЕ ВСТАНОВЛЕНО", 1)[0]
        self.assertIn("- Серверів зі встановленим 1С / BAF: 2", output)
        self.assertIn("- Серверів без 1С / BAF: 1", output)
        self.assertLess(installed_section.index("192.168.2.20 | server-2"), installed_section.index("192.168.10.2 | server-10"))
        self.assertNotIn("192.168.3.5 | server-3", installed_section)
        self.assertIn("- operator", installed_section)
        self.assertNotIn(r"- DOMAIN\operator", installed_section)
        self.assertNotIn(r"C:\Program Files\1cv8", output)
        self.assertNotIn("item.path", self.report)
        self.assertNotIn("account.status_source", self.report)
        self.assertNotIn("account.granted_by", self.report)

    def test_not_installed_list_is_the_final_report_section(self):
        output = render_report(
            self.report,
            {
                "job_title": "Inventory",
                "results": [result("missing", "192.168.3.5", False)],
                "ignored_results": [
                    {"host": "offline", "status": "Error", "data": {}, "log": "No connection"}
                ],
            },
        )

        final_heading = "1С / BAF — НЕ ВСТАНОВЛЕНО"
        self.assertGreater(output.index(final_heading), output.index("ПОМИЛКИ ПЕРЕВІРКИ"))
        self.assertIn("- 192.168.3.5 | missing", output.split(final_heading, 1)[1])
        self.assertTrue(output.rstrip().endswith("[[/WINHUB_REPORT]]"))

    def test_warnings_are_grouped_by_server_at_the_end(self):
        server = result("server-2", "192.168.2.20", True)
        server["data"]["warnings"] = ["Directory lookup failed"]
        output = render_report(
            self.report,
            {"job_title": "Inventory", "results": [server], "ignored_results": []},
        )

        warning_heading = "ПОПЕРЕДЖЕННЯ"
        card = output.split(warning_heading, 1)[0]
        warnings = output.split(warning_heading, 1)[1]
        self.assertNotIn("Directory lookup failed", card)
        self.assertIn("192.168.2.20 | server-2", warnings)
        self.assertIn("- Directory lookup failed", warnings)
        self.assertGreater(output.index(warning_heading), output.index("1С / BAF — НЕ ВСТАНОВЛЕНО"))


if __name__ == "__main__":
    unittest.main()
