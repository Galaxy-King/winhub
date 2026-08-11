"""Web-process boundary for restricted report rendering."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from core.config import Config


def render_report_template(template_string, context):
    mode = str(getattr(Config, "REPORT_RENDERER_MODE", "subprocess") or "subprocess").lower()
    if mode == "inprocess":
        from core.report_renderer import render_report

        return render_report(template_string, context)
    if mode != "subprocess":
        raise RuntimeError("Unsupported REPORT_RENDERER_MODE")

    worker = Path(__file__).with_name("report_renderer.py")
    request_body = json.dumps({"template": template_string, "context": context}, ensure_ascii=False, default=str)
    clean_env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    if os.name == "nt":
        clean_env["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")
    else:
        clean_env["LANG"] = os.environ.get("LANG", "C.UTF-8")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    with tempfile.TemporaryDirectory(prefix="winhub-report-") as temp_dir:
        completed = subprocess.run(
            [sys.executable, "-I", str(worker), "--worker"],
            input=request_body,
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=int(getattr(Config, "REPORT_RENDERER_TIMEOUT_SECONDS", 10)),
            cwd=temp_dir,
            env=clean_env,
            creationflags=creationflags,
            check=False,
        )
    try:
        response = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("Report renderer returned an invalid response") from exc
    if completed.returncode != 0 or not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "Report renderer failed")[:1000])
    return str(response.get("output") or "")
