"""Standalone parser worker. Never runs the submitted script; no app/DB imports."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

# This directory is root-owned on Debian; -I excludes user-controlled Python paths.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ai_template_contract import MAX_BUNDLE_BYTES, CONTRACT_VERSION, bundle_hash, validate_bundle, report_fixture
from report_renderer import render_report

VALIDATOR_VERSION = "1"
MAX_CAPTURE = 262144


def run_parser(args, scratch):
    env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(scratch),
           "DOTNET_EnableDiagnostics": "0", "POWERSHELL_TELEMETRY_OPTOUT": "1",
           "PSModulePath": "/usr/local/share/powershell/Modules:/opt/microsoft/powershell/7/Modules"}
    if os.name == "nt":
        env["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(args, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=os.name != "nt",
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                import signal
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
            raise ValueError("Parser timeout")
        output.seek(0)
        raw = output.read(MAX_CAPTURE + 1)
        if len(raw) > MAX_CAPTURE:
            raise ValueError("Parser output exceeds limit")
        return process.returncode, raw.decode("utf-8-sig", errors="replace")


def validate(value):
    value = validate_bundle(value)
    diagnostics = []
    available = True
    def add(severity, message):
        diagnostics.append({"severity": severity, "message": str(message)[:1500]})
    with tempfile.TemporaryDirectory(prefix="winhub-validate-") as scratch:
        language, code = value["language"], value["code"]
        if language != "jinja":
            path = Path(scratch) / ("input.ps1" if language == "powershell" else "input.sh")
            path.write_text(code, encoding="utf-8-sig" if language == "powershell" else "utf-8")
            if language == "powershell":
                binary = shutil.which("pwsh")
                if not binary:
                    available = False
                    add("unavailable", "PowerShell parser is not installed on the validator host (pwsh).")
                else:
                    rc, output = run_parser([binary, "-NoLogo", "-NoProfile", "-NonInteractive", "-File",
                                             str(Path(__file__).with_name("validate_powershell.ps1")), str(path)], scratch)
                    try:
                        parsed = json.loads(output)
                        for item in parsed["diagnostics"][:30]:
                            add(item["severity"], item["message"])
                        if rc or not parsed["syntax_ok"]:
                            add("error", "PowerShell syntax validation failed")
                    except (ValueError, KeyError, TypeError):
                        add("error", "PowerShell parser returned an invalid response")
                    add("warning", "Parsed with PowerShell 7; Windows PowerShell 5.1 runtime/API compatibility still requires operator review")
            else:
                binary = shutil.which("bash")
                if not binary:
                    available = False
                    add("unavailable", "Bash parser is unavailable")
                else:
                    rc, output = run_parser([binary, "--noprofile", "--norc", "-n", str(path)], scratch)
                    if rc:
                        add("error", output or "Bash syntax validation failed")
                    shellcheck = shutil.which("shellcheck")
                    if shellcheck:
                        rc, output = run_parser([shellcheck, "--norc", "--shell=bash", "--format=json", str(path)], scratch)
                        try:
                            for item in json.loads(output)[:30]:
                                add("warning", f"ShellCheck SC{item['code']} line {item['line']}: {item['message']}")
                            if rc not in (0, 1):
                                add("error", "ShellCheck failed")
                        except (ValueError, TypeError, KeyError):
                            add("error", "ShellCheck returned an invalid response")
                    else:
                        add("warning", "ShellCheck unavailable; only Bash syntax was checked")
            if re.search(r"(?i)invoke-expression|downloadstring|\beval\b|\brm\s+-[^\n]*r|remove-item|restart-computer|\breboot\b|\bshutdown\b", code):
                add("warning", "Review dynamic execution, deletion or restart operations manually; static checks cannot establish safety")
        report = code if language == "jinja" else value["report_template"]
        if report:
            try:
                render_report(report, report_fixture(value["sample_result"]))
            except Exception as exc:
                add("error", f"Report fixture: {exc}")
    ok = available and not any(d["severity"] == "error" for d in diagnostics)
    return {"ok": ok, "status": "checked" if ok else "invalid" if available else "unavailable",
            "diagnostics": diagnostics[:40], "code_hash": bundle_hash(value),
            "contract_version": CONTRACT_VERSION, "validator_version": VALIDATOR_VERSION,
            "executed": False}


def worker():
    # cgroup MemoryMax enforces RAM; RLIMIT_AS would prevent the .NET parser starting.
    if os.name != "posix":
        raise RuntimeError("The production validator requires POSIX isolation")
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (25, 26))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_CAPTURE, MAX_CAPTURE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    raw = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    if len(raw) > MAX_BUNDLE_BYTES:
        raise ValueError("Validator request too large")
    result = validate(json.loads(raw))
    sys.stdout.write(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    try:
        worker()
    except Exception:
        sys.stdout.write(json.dumps({"ok": False, "status": "error", "executed": False,
                                    "diagnostics": [{"severity": "error", "message": "Isolated validator failed"}]}))
        raise SystemExit(2)
