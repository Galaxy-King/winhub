"""Only a Unix socket may validate untrusted generated code. No local fallback."""
import json
import os
import socket
import time

from core.ai_template_contract import MAX_BUNDLE_BYTES, bundle_hash, validate_bundle
from core.config import Config


def validate_code_bundle(bundle):
    validate_bundle(bundle)
    body = json.dumps(bundle, ensure_ascii=False).encode()
    if len(body) > MAX_BUNDLE_BYTES:
        raise ValueError("Validator request too large")
    path = Config.CODE_VALIDATOR_SOCKET
    if os.name != "posix" or not os.path.isabs(path):
        raise RuntimeError("Isolated validator requires the Debian Unix socket service")
    deadline = time.monotonic() + 40
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(40)
        connection.connect(path)
        connection.sendall(body)
        connection.shutdown(socket.SHUT_WR)
        output = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Validator deadline exceeded")
            connection.settimeout(remaining)
            part = connection.recv(8192)
            if not part:
                break
            output.extend(part)
            if len(output) > 65536:
                raise ValueError("Validator response too large")
    result = json.loads(output)
    if result.get("code_hash") != bundle_hash(bundle) or result.get("executed") is not False:
        raise ValueError("Invalid validator response or stale code hash")
    return result
