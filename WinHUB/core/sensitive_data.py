"""Central redaction policy for task output, reports, and history APIs."""

import json
import re


MASK = "***"
SENSITIVE_NAME_PATTERN = re.compile(
    r"(?:^|[\s_\-.])(?:password|passwd|passphrase|pwd|secret|token|credential|api[\s_-]?key|private[\s_-]?key|пароль)(?:$|[\s_\-.])",
    re.IGNORECASE,
)
SENSITIVE_KEYWORD = (
    r"(?:temporary[\s_-]*)?"
    r"(?:password|passwd|passphrase|pwd|secret|token|credential|api[\s_-]?key|private[\s_-]?key|пароль)"
)
HTML_SENSITIVE_TEXT_PATTERNS = (
    # Common report markup: <td>Password</td><td><code>value</code></td>
    # or <strong>Token:</strong> value. Run before the plain-text rules so a
    # closing tag is never mistaken for the sensitive value.
    re.compile(
        rf"(\b{SENSITIVE_KEYWORD}\b\s*(?:(?:[:=\-]|\bis\b)\s*)?"
        r"</(?:td|th|dt|label|strong|b|span|div|p)>\s*"
        r"(?:<(?:td|dd|span|div|p|code|pre)\b[^>]*>\s*)*)([^<\r\n]+)",
        re.IGNORECASE,
    ),
)
SENSITIVE_TEXT_PATTERNS = (
    re.compile(
        rf"(\b{SENSITIVE_KEYWORD}\b\s*(?:[:=\-]|\bis\b)\s*)"
        r"(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)",
        re.IGNORECASE,
    ),
    re.compile(r"(\bPass\s*:\s*)([^\s|]+)", re.IGNORECASE),
)


def is_sensitive_name(name):
    value = str(name or "").strip()
    value = re.sub(r"(?<=[a-zа-яіїєґ0-9])(?=[A-ZА-ЯІЇЄҐ])", "_", value)
    return bool(SENSITIVE_NAME_PATTERN.search(value))


def mask_sensitive_value(name, value):
    return MASK if is_sensitive_name(name) else value


def mask_sensitive_object(value):
    if isinstance(value, dict):
        return {
            key: MASK if is_sensitive_name(key) else mask_sensitive_object(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [mask_sensitive_object(item) for item in value]
    return value


def masked_variables(variables):
    return {
        key: mask_sensitive_value(key, value)
        for key, value in (variables or {}).items()
    }


def mask_sensitive_text(text):
    source = str(text or "")
    if not source:
        return source

    # Preserve structured results structurally so nested secret fields cannot evade
    # line-oriented regular expressions.
    try:
        parsed = json.loads(source)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(mask_sensitive_object(parsed), ensure_ascii=False)

    masked = source
    for pattern in HTML_SENSITIVE_TEXT_PATTERNS:
        masked = pattern.sub(r"\1***", masked)
    for pattern in SENSITIVE_TEXT_PATTERNS:
        masked = pattern.sub(r"\1***", masked)
    return masked
