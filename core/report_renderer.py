"""Restricted report-template renderer.

This module intentionally has no Flask or database imports.  Production calls it
in a short-lived isolated Python process so a malformed template cannot inherit
the web process' application objects or secrets.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from jinja2 import StrictUndefined, nodes
from jinja2.exceptions import SecurityError, TemplateError
from jinja2.sandbox import ImmutableSandboxedEnvironment


MAX_TEMPLATE_BYTES = 512 * 1024
MAX_CONTEXT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_RANGE_ITEMS = 4096

ALLOWED_FILTERS = {
    "default",
    "escape",
    "e",
    "join",
    "length",
    "list",
    "lower",
    "rejectattr",
    "round",
    "selectattr",
}
ALLOWED_TESTS = {"boolean", "defined", "false", "mapping", "none", "number", "string", "true", "undefined"}
FORBIDDEN_NODES = (nodes.CallBlock, nodes.Extends, nodes.FromImport, nodes.Import, nodes.Include, nodes.Macro)


def report_range(*args: Any) -> range:
    """Provide integer-only, bounded iteration for tables such as subnet maps."""
    if not 1 <= len(args) <= 3 or any(type(value) is not int for value in args):
        raise TypeError("Report range accepts one to three integer arguments")
    try:
        values = range(*args)
        item_count = len(values)
    except (OverflowError, ValueError) as exc:
        raise ValueError("Invalid report range") from exc
    if item_count > MAX_RANGE_ITEMS:
        raise ValueError(f"Report range cannot contain more than {MAX_RANGE_ITEMS} items")
    return values


class ReportSandbox(ImmutableSandboxedEnvironment):
    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        if not attr or attr.startswith("_"):
            return False
        if isinstance(obj, str):
            return attr == "split"
        if isinstance(obj, (dict, list, tuple)):
            return not callable(value)
        # Namespace attributes are data slots used by the bundled report templates.
        if obj.__class__.__module__ == "jinja2.utils" and obj.__class__.__name__ == "Namespace":
            return not callable(value)
        return False

    def is_safe_callable(self, obj: Any) -> bool:
        owner = getattr(obj, "__self__", None)
        safe_split = isinstance(owner, str) and getattr(obj, "__name__", "") == "split"
        safe_namespace = getattr(obj, "__module__", "") == "jinja2.utils" and getattr(obj, "__name__", "") == "Namespace"
        return safe_split or safe_namespace or obj is report_range


def _environment() -> ReportSandbox:
    env = ReportSandbox(
        autoescape=True,
        undefined=StrictUndefined,
        enable_async=False,
        trim_blocks=False,
        lstrip_blocks=False,
    )
    env.filters = {name: value for name, value in env.filters.items() if name in ALLOWED_FILTERS}
    env.tests = {name: value for name, value in env.tests.items() if name in ALLOWED_TESTS}
    namespace_factory = env.globals.get("namespace")
    env.globals.clear()
    if namespace_factory is not None:
        env.globals["namespace"] = namespace_factory
    env.globals["range"] = report_range
    return env


def validate_report_template(template_string: str) -> None:
    encoded = str(template_string or "").encode("utf-8")
    if len(encoded) > MAX_TEMPLATE_BYTES:
        raise SecurityError("Report template is too large")

    env = _environment()
    tree = env.parse(template_string)
    for node in tree.find_all(FORBIDDEN_NODES):
        raise SecurityError(f"Jinja node {node.__class__.__name__} is not allowed in report templates")
    for node in tree.find_all(nodes.Name):
        if node.name.startswith("_"):
            raise SecurityError("Private Jinja names are not allowed")
    for node in tree.find_all(nodes.Getattr):
        if node.attr.startswith("_"):
            raise SecurityError("Private attributes are not allowed")
    for node in tree.find_all(nodes.Call):
        safe_namespace = isinstance(node.node, nodes.Name) and node.node.name == "namespace"
        safe_range = isinstance(node.node, nodes.Name) and node.node.name == "range"
        safe_split = isinstance(node.node, nodes.Getattr) and node.node.attr == "split"
        if not (safe_namespace or safe_range or safe_split):
            raise SecurityError("Function calls are not allowed in report templates")
    env.from_string(template_string)


def render_report(template_string: str, context: dict[str, Any]) -> str:
    if not isinstance(context, dict):
        raise ValueError("Report context must be an object")
    context_size = len(json.dumps(context, ensure_ascii=False, default=str).encode("utf-8"))
    if context_size > MAX_CONTEXT_BYTES:
        raise ValueError("Report context is too large")

    validate_report_template(template_string)
    output = _environment().from_string(template_string).render(**context)
    if len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("Rendered report is too large")
    return output


def _apply_resource_limits(required: bool = False) -> None:
    if os.name == "posix":
        try:
            import resource

            resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_CPU, (8, 9))
            resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
            resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
            if hasattr(resource, "RLIMIT_NPROC"):
                resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))
        except (ImportError, OSError, ValueError) as exc:
            if required:
                raise RuntimeError("Required renderer resource limits could not be applied") from exc
    elif required:
        raise RuntimeError("Required renderer resource limits are unavailable on this platform")


def _worker(require_limits: bool = False) -> int:
    try:
        _apply_resource_limits(required=require_limits)
        request = json.load(sys.stdin)
        output = render_report(str(request.get("template") or ""), request.get("context") or {})
        json.dump({"ok": True, "output": output}, sys.stdout, ensure_ascii=False)
        return 0
    except (SecurityError, TemplateError, TypeError, ValueError) as exc:
        json.dump({"ok": False, "error": str(exc)[:1000]}, sys.stdout, ensure_ascii=False)
        return 2
    except Exception:
        json.dump({"ok": False, "error": "Report renderer failed"}, sys.stdout, ensure_ascii=False)
        return 3


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--require-limits", action="store_true")
    args = parser.parse_args()
    raise SystemExit(_worker(require_limits=args.require_limits) if args.worker else 64)
