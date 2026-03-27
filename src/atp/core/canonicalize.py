"""JCS (RFC 8785) canonicalization for ATP messages."""

import json
import math


class _JCSEncoder(json.JSONEncoder):
    """JSON encoder conforming to RFC 8785 (JCS) number serialization.

    - Rejects NaN and Infinity (not valid JSON per RFC 8259).
    - Normalizes -0.0 to 0.0.
    - Integers rendered without decimal point.
    """

    def default(self, o):
        raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

    def encode(self, o):
        return self._encode_value(o)

    def _encode_value(self, o):
        if isinstance(o, dict):
            items = sorted(o.items())
            entries = ",".join(
                f"{self._encode_value(k)}:{self._encode_value(v)}"
                for k, v in items
            )
            return "{" + entries + "}"
        elif isinstance(o, (list, tuple)):
            entries = ",".join(self._encode_value(v) for v in o)
            return "[" + entries + "]"
        elif isinstance(o, str):
            return json.dumps(o, ensure_ascii=False)
        elif isinstance(o, bool):
            return "true" if o else "false"
        elif o is None:
            return "null"
        elif isinstance(o, int):
            return str(o)
        elif isinstance(o, float):
            if math.isnan(o) or math.isinf(o):
                raise ValueError(
                    f"JCS (RFC 8785) does not allow {o!r} — "
                    "NaN and Infinity are not valid JSON values"
                )
            if o == 0.0:
                return "0"  # Normalize -0.0 to 0
            # Use repr-like formatting that avoids unnecessary trailing zeros
            # but always produces valid JSON numbers
            if o == int(o) and abs(o) < 2**53:
                return str(int(o))
            return repr(o)
        else:
            raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")


def canonicalize(data: dict) -> bytes:
    """JCS (RFC 8785) canonicalization.

    Produces a deterministic JSON representation:
    - Object keys sorted lexicographically (recursive)
    - No insignificant whitespace
    - Numbers: no NaN/Infinity, -0.0 normalized to 0, integers without decimal
    - Strings use minimal escaping

    Returns UTF-8 encoded bytes.

    Raises ValueError for non-finite floats (NaN, Infinity).
    """
    encoder = _JCSEncoder()
    return encoder.encode(data).encode("utf-8")
