"""Launch reasons are audit metadata, never executable task input."""
import unicodedata

MAX_LAUNCH_REASON_LENGTH = 2000


def validate_launch_reason(value):
    if not isinstance(value, str):
        raise ValueError("Launch reason is required (launch_reason).")
    reason = value.strip()
    if not reason or not any(not c.isspace() and unicodedata.category(c)[0] != "C" for c in reason):
        raise ValueError("Launch reason is required (launch_reason).")
    if len(reason) > MAX_LAUNCH_REASON_LENGTH:
        raise ValueError(f"Launch reason must not exceed {MAX_LAUNCH_REASON_LENGTH} characters.")
    if any(unicodedata.category(c) in {"Cc", "Cs"} and c not in "\r\n\t" for c in reason):
        raise ValueError("Launch reason contains unsupported control characters.")
    return reason
