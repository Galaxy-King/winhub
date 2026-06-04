import json


def encryption_status_from_host_info(host_info):
    if isinstance(host_info, str):
        try:
            host_info = json.loads(host_info or "{}")
        except Exception:
            host_info = {}

    security = {}
    if isinstance(host_info, dict):
        security = host_info.get("security") or {}

    bitlocker = security.get("bitlocker") or {}
    bitlocker_status = str(bitlocker.get("status") or "").lower()
    bitlocker_text = str(security.get("bitlocker_summary") or "")
    bitlocker_lower = bitlocker_text.lower()
    bitlocker_on = (
        bitlocker_status == "encrypted"
        or "protection on" in bitlocker_lower
        or "fully encrypted" in bitlocker_lower
        or "percentage encrypted: 100" in bitlocker_lower
    )
    bitlocker_partial = (
        bitlocker_status == "partial"
        or "encryption in progress" in bitlocker_lower
        or "percentage encrypted:" in bitlocker_lower and "percentage encrypted: 0" not in bitlocker_lower
    )
    veracrypt = bool(security.get("veracrypt_detected"))
    truecrypt = bool(security.get("truecrypt_detected"))

    if bitlocker_on or veracrypt or truecrypt:
        status = "Encrypted"
        level = "encrypted"
    elif bitlocker_partial:
        status = "Partial"
        level = "partial"
    elif bitlocker_status == "not_encrypted" or (bitlocker_text and bitlocker_text not in ("unavailable", "timeout")):
        status = "Not encrypted"
        level = "none"
    else:
        status = "Unknown"
        level = "unknown"

    methods = []
    if bitlocker_on or bitlocker_partial:
        methods.append("BitLocker")
    if veracrypt:
        methods.append("VeraCrypt")
    if truecrypt:
        methods.append("TrueCrypt")
    return {"status": status, "level": level, "methods": methods}


def apply_endpoint_encryption_status(endpoint, host_info):
    status = encryption_status_from_host_info(host_info)
    endpoint.encryption_status = status.get("status") or "Unknown"
    endpoint.encryption_level = status.get("level") or "unknown"
    endpoint.encryption_methods = ",".join(status.get("methods") or [])
    return status
