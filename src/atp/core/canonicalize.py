"""JCS (RFC 8785) canonicalization for ATP messages."""

import json


def canonicalize(data: dict) -> bytes:
    """JCS (RFC 8785) canonicalization.

    Produces a deterministic JSON representation:
    - Object keys sorted lexicographically
    - No insignificant whitespace
    - Numbers use Python's json default (no trailing zeros)
    - Strings use minimal escaping
    - Recursive for nested dicts/lists

    Returns UTF-8 encoded bytes.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
