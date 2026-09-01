"""Open WebUI integration with encrypted credentials and outbound policy checks."""

from __future__ import annotations

import json
import os
import tempfile
from urllib.parse import urlsplit, urlunsplit

import requests

from core.config import Config
from core.outbound_security import pinned_outbound_url
from core.security import sec_manager


AI_PROVIDER_FILE = os.path.join(Config.DATA_DIR, "infra_ai_provider.json")


def _allowed_schemes():
    return ("https", "http") if Config.AI_ALLOW_INSECURE_HTTP else ("https",)


def normalize_base_url(value):
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in _allowed_schemes():
        if parsed.scheme.lower() == "http":
            raise ValueError("HTTP for the AI provider is disabled; enable AI_ALLOW_INSECURE_HTTP only on a protected network")
        raise ValueError("AI provider URL must use HTTPS")
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Invalid AI provider URL")
    path = parsed.path.rstrip("/")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, path, "", ""))


def load_ai_provider(include_secret=False):
    settings = {"enabled": False, "base_url": "", "model": "", "api_key": ""}
    try:
        with open(AI_PROVIDER_FILE, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
        if isinstance(raw, dict):
            settings.update({
                "enabled": bool(raw.get("enabled")),
                "base_url": str(raw.get("base_url") or ""),
                "model": str(raw.get("model") or ""),
                "api_key": sec_manager.decrypt_data(str(raw.get("api_key") or "")),
            })
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        settings["configuration_error"] = True
    if include_secret:
        return settings
    return {
        "enabled": settings["enabled"],
        "base_url": settings["base_url"],
        "model": settings["model"],
        "has_api_key": bool(settings["api_key"]),
        "configuration_error": bool(settings.get("configuration_error")),
    }


def save_ai_provider(data):
    current = load_ai_provider(include_secret=True)
    base_url = normalize_base_url(data.get("base_url"))
    model = str(data.get("model") or "").strip()
    if not model or len(model) > 150:
        raise ValueError("AI model is required and must be at most 150 characters")
    submitted_key = str(data.get("api_key") or "").strip()
    if len(submitted_key) > 4096:
        raise ValueError("Open WebUI API key is too long")
    if current.get("base_url"):
        old = urlsplit(str(current["base_url"]))
        new = urlsplit(base_url)
        old_origin = (old.scheme, old.hostname, old.port or (443 if old.scheme == "https" else 80))
        new_origin = (new.scheme, new.hostname, new.port or (443 if new.scheme == "https" else 80))
        if old_origin != new_origin and not submitted_key:
            raise ValueError("AI provider origin changed; re-enter the API key")
    api_key = submitted_key or current.get("api_key", "")
    if not api_key:
        raise ValueError("Open WebUI API key is required")
    encrypted_key = sec_manager.encrypt_data(api_key)
    if not encrypted_key:
        raise ValueError("WinHUB could not encrypt the Open WebUI API key")
    stored = {
        "enabled": bool(data.get("enabled")),
        "base_url": base_url,
        "model": model,
        "api_key": encrypted_key,
    }
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".infra_ai_", suffix=".json", dir=Config.DATA_DIR, text=True)
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(stored, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, AI_PROVIDER_FILE)
        if os.name != "nt":
            os.chmod(AI_PROVIDER_FILE, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
    return load_ai_provider()


class OpenWebUIClient:
    def __init__(self, settings=None):
        self.settings = settings or load_ai_provider(include_secret=True)
        self.base_url = normalize_base_url(self.settings.get("base_url"))
        self.api_key = str(self.settings.get("api_key") or "").strip()
        self.model = str(self.settings.get("model") or "").strip()
        if not self.api_key:
            raise ValueError("Open WebUI API key is not configured")
        self.session = requests.Session()
        self.session.trust_env = False

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        headers = dict(kwargs.pop("headers", {}) or {})
        headers["Authorization"] = f"Bearer {self.api_key}"
        headers.setdefault("Accept", "application/json")
        with pinned_outbound_url(url, purpose="Open WebUI API", allowed_schemes=_allowed_schemes()):
            response = self.session.request(
                method,
                url,
                headers=headers,
                timeout=Config.AI_REQUEST_TIMEOUT_SECONDS,
                allow_redirects=False,
                **kwargs,
            )
        if response.is_redirect:
            raise ValueError("Open WebUI redirects are not allowed")
        if response.status_code >= 400:
            raise ValueError(f"Open WebUI returned HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise ValueError("Open WebUI returned an invalid JSON response") from exc

    def models(self):
        payload = self._request("GET", "/api/models")
        rows = payload.get("data", payload) if isinstance(payload, dict) else payload
        return sorted({str(item.get("id")) for item in (rows or []) if isinstance(item, dict) and item.get("id")})

    def health(self):
        url = f"{self.base_url}/health"
        with pinned_outbound_url(url, purpose="Open WebUI health check", allowed_schemes=_allowed_schemes()):
            response = self.session.get(url, timeout=min(Config.AI_REQUEST_TIMEOUT_SECONDS, 20), allow_redirects=False)
        return response.status_code == 200

    def chat_completion(self, messages, model=None):
        payload = self._request("POST", "/api/chat/completions", json={
            "model": model or self.model,
            "messages": messages,
            "stream": False,
        })
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Open WebUI response does not contain assistant content") from exc
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Open WebUI returned an empty report")
        encoded = content.encode("utf-8")
        if len(encoded) > Config.AI_MAX_OUTPUT_BYTES:
            raise ValueError("AI report exceeds the configured output limit")
        return content.strip()
