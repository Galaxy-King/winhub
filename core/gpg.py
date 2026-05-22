import os
import subprocess
import tempfile
import urllib.parse
import urllib.request
import ssl

from core.config import Config


def hidden_subprocess_kwargs():
    return {"creationflags": 0x08000000} if os.name == "nt" else {}


def gpg_home():
    path = getattr(Config, "GPG_HOME", None) or os.path.join(Config.DATA_DIR, "gnupg")
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def gpg_env():
    env = os.environ.copy()
    env["GNUPGHOME"] = gpg_home()
    return env


def gpg_path():
    return getattr(Config, "GPG_PATH", None) or "gpg"


def validate_gpg():
    path = gpg_path()
    if not path or (os.path.sep in path and not os.path.exists(path)):
        return False, f"GPG executable not found: {path}"
    try:
        proc = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            env=gpg_env(),
            **hidden_subprocess_kwargs(),
        )
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout or "GPG version check failed").strip()
        return True, "GPG is available"
    except Exception as exc:
        return False, str(exc)


def import_public_key(key_text):
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in (key_text or ""):
        return False, "No PGP public key block found."
    fd, tmp_path = tempfile.mkstemp(suffix=".asc")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(key_text)
        proc = subprocess.run(
            [gpg_path(), "--batch", "--yes", "--import", tmp_path],
            capture_output=True,
            text=True,
            timeout=15,
            env=gpg_env(),
            **hidden_subprocess_kwargs(),
        )
        output = (proc.stderr or proc.stdout or "").strip()
        if proc.returncode != 0:
            return False, output or f"GPG import failed with exit code {proc.returncode}"
        return True, output or "Key imported successfully."
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass


def fetch_public_key(keyserver, search):
    base_url = (keyserver or "").strip() or "hkps://keys.openpgp.org"
    lookup = (search or "").strip()
    if not lookup:
        return False, "Search value is required."
    base_url = base_url.replace("hkps://", "https://").replace("hkp://", "http://").rstrip("/")
    api_url = f"{base_url}/pks/lookup?op=get&options=mr&search={urllib.parse.quote(lookup)}"
    try:
        context = ssl.create_default_context()
        req = urllib.request.Request(api_url, headers={"User-Agent": "WinHUB GPG Key Import"})
        with urllib.request.urlopen(req, timeout=15, context=context) as response:
            key_text = response.read().decode("utf-8", errors="replace")
    except Exception as exc:
        return False, f"Keyserver fetch failed: {exc}"
    return import_public_key(key_text)


def list_public_keys():
    proc = subprocess.run(
        [gpg_path(), "--batch", "--with-colons", "--fingerprint", "--list-keys"],
        capture_output=True,
        text=True,
        timeout=10,
        env=gpg_env(),
        **hidden_subprocess_kwargs(),
    )
    if proc.returncode != 0:
        return False, (proc.stderr or "Could not list GPG keys").strip(), []

    keys = []
    current = None
    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if not parts:
            continue
        record_type = parts[0]
        if record_type == "pub":
            current = {
                "key_id": parts[4] if len(parts) > 4 else "",
                "created": parts[5] if len(parts) > 5 else "",
                "expires": parts[6] if len(parts) > 6 else "",
                "uids": [],
                "fingerprint": "",
            }
            keys.append(current)
        elif record_type == "fpr" and current and not current["fingerprint"]:
            current["fingerprint"] = parts[9] if len(parts) > 9 else ""
        elif record_type == "uid" and current:
            current["uids"].append(parts[9] if len(parts) > 9 else "")
    return True, "OK", keys


def delete_public_key(fingerprint):
    value = (fingerprint or "").strip()
    if not value:
        return False, "Fingerprint is required."
    proc = subprocess.run(
        [gpg_path(), "--batch", "--yes", "--delete-keys", value],
        capture_output=True,
        text=True,
        timeout=15,
        env=gpg_env(),
        **hidden_subprocess_kwargs(),
    )
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "Delete failed").strip()
    return True, "Key deleted."
