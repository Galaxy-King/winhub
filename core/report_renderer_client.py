"""Web-process boundary for restricted report rendering."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from core.config import Config


MAX_RENDERER_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RENDERER_REQUEST_BYTES = 10 * 1024 * 1024


def _decode_response(raw_response):
    try:
        response = json.loads(raw_response or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("Report renderer returned an invalid response") from exc
    if not response.get("ok"):
        raise RuntimeError(str(response.get("error") or "Report renderer failed")[:1000])
    return str(response.get("output") or "")


def _render_via_service(request_body):
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        raise RuntimeError("Report renderer service requires a Unix socket")
    socket_path = str(getattr(Config, "REPORT_RENDERER_SOCKET", "/run/winhub-renderer.sock") or "").strip()
    if not socket_path or not os.path.isabs(socket_path):
        raise RuntimeError("REPORT_RENDERER_SOCKET must be an absolute path")

    timeout = int(getattr(Config, "REPORT_RENDERER_TIMEOUT_SECONDS", 10))
    chunks = []
    total = 0
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(socket_path)
        connection.sendall(request_body.encode("utf-8"))
        connection.shutdown(socket.SHUT_WR)
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RENDERER_RESPONSE_BYTES:
                raise RuntimeError("Report renderer response is too large")
            chunks.append(chunk)
    return _decode_response(b"".join(chunks).decode("utf-8"))


def render_report_template(template_string, context):
    mode = str(getattr(Config, "REPORT_RENDERER_MODE", "subprocess") or "subprocess").lower()
    if mode == "inprocess":
        from core.report_renderer import render_report

        return render_report(template_string, context)
    request_body = json.dumps({"template": template_string, "context": context}, ensure_ascii=False, default=str)
    if len(request_body.encode("utf-8")) > MAX_RENDERER_REQUEST_BYTES:
        raise RuntimeError("Report renderer request is too large")
    if mode == "service":
        return _render_via_service(request_body)
    if mode != "subprocess":
        raise RuntimeError("Unsupported REPORT_RENDERER_MODE")

    worker = Path(__file__).with_name("report_renderer.py")
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
    if completed.returncode != 0 and not completed.stdout:
        raise RuntimeError("Report renderer failed")
    return _decode_response(completed.stdout)
