"""Generate data/attack_db.json from a MITRE CTI STIX bundle.

Usage:
    ATTACK_MAPPER_STIX=path/to/enterprise-attack.json \
        python -m attack_mapper.build_db
"""

from __future__ import annotations

import json
import os

from .attack_loader import _load_stix  # noqa: F401 (reuse the parser)

DEFAULT_OUT = os.path.join(os.path.dirname(__file__), "data", "attack_db.json")


def main() -> int:
    stix = os.environ.get("ATTACK_MAPPER_STIX")
    if not stix or not os.path.isfile(stix):
        print(
            "Set ATTACK_MAPPER_STIX to a downloaded enterprise-attack.json "
            "(e.g. https://github.com/mitre/cti).",
            file=__import__("sys").stderr,
        )
        return 1
    db = _load_stix(stix)
    out = os.path.abspath(DEFAULT_OUT)
    compact = {
        "version": db.version,
        "tactics": db.tactics,
        "techniques": db.techniques,
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(compact, fh, indent=1)
    print(
        f"Wrote {len(db.techniques)} techniques / {len(db.tactics)} tactics "
        f"to {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
