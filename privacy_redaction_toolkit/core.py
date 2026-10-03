"""Recursive sensitive-key filtering and explicitly scoped pattern redaction."""

import hashlib, hmac, ipaddress, json, re, os, tempfile
from pathlib import Path

SENSITIVE = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "apikey",
    "ssn",
}
PATTERNS = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("bearer", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.I)),
    ("token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9_-]{12,})\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]


def redact(document, salt=None):
    if salt is not None and (not isinstance(salt, bytes) or len(salt) < 16):
        raise ValueError("Correlation salt must contain at least sixteen bytes")
    counts = {}

    def replacement(kind, value):
        counts[kind] = counts.get(kind, 0) + 1
        if salt is None:
            return "[" + kind.upper() + "]"
        digest = hmac.new(
            salt, (kind + "\x00" + value).encode(), hashlib.sha256
        ).hexdigest()[:16]
        return "[" + kind.upper() + ":" + digest + "]"

    def text(value):
        for kind, pattern in PATTERNS:

            def replace(match):
                if kind == "ipv4":
                    try:
                        ipaddress.IPv4Address(match[0])
                    except ValueError:
                        return match[0]
                return replacement(kind, match[0])

            value = pattern.sub(replace, value)
        return value

    def walk(value):
        if isinstance(value, dict):
            return {
                key: (
                    replacement(
                        "sensitive", json.dumps(child, sort_keys=True, allow_nan=False)
                    )
                    if key.lower().replace("-", "_") in SENSITIVE
                    else walk(child)
                )
                for key, child in value.items()
            }
        if isinstance(value, list):
            return [walk(child) for child in value]
        if isinstance(value, str):
            return text(value)
        return value

    result = walk(document)
    return {"document": result, "replacements": counts}


def write_redacted(source, target, salt_file=None):
    source, target = Path(source), Path(target)
    if source.resolve() == target.resolve():
        raise ValueError("Output must not overwrite input")
    if salt_file and Path(salt_file).resolve() in [source.resolve(), target.resolve()]:
        raise ValueError("Salt file must be separate from input and output")
    salt = Path(salt_file).read_bytes() if salt_file else None
    result = redact(json.loads(source.read_text(encoding="utf-8")), salt)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=target.parent, delete=False
    ) as out:
        temporary = Path(out.name)
        json.dump(result["document"], out, indent=2, allow_nan=False)
    try:
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return {"output": str(target), "replacements": result["replacements"]}
