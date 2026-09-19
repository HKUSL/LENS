"""Per-AVP standard-document lookup.

Used by the Keyword Retrieval configuration. Given a Diameter target field
(message + AVP path), find the corresponding ``.docx`` under
``data/diameter/{s6a,cx}/avps/`` and return its full text. Returns None if no
matching document exists.

The expected filename is ``<MSG_ABBR>_<path-with-dots-as-underscores>.docx``.
Example: ``IDR_Subscription-Data_APN-Configuration-Profile_APN-Configuration_Service-Selection.docx``.
"""
from __future__ import annotations

import os
from typing import Optional

from .common import EVAL_DIR
from .samples import Sample, _parse_message
from .specs import get_full_text


DATA_DIR = os.path.join(EVAL_DIR, "data", "diameter")


def _avp_dir(interface: str) -> Optional[str]:
    iface = (interface or "").lower()
    if iface not in {"s6a", "cx"}:
        return None
    path = os.path.join(DATA_DIR, iface, "avps")
    return path if os.path.isdir(path) else None


def _expected_filename(sample: Sample) -> Optional[str]:
    _, abbr = _parse_message(sample.message_full)
    if not abbr or not sample.target_path:
        return None
    leaf_path = sample.target_path.replace(".", "_")
    return f"{abbr}_{leaf_path}.docx"


def find_spec_doc(sample: Sample) -> Optional[str]:
    """Return the absolute path to the spec docx for ``sample``, or None."""
    avp_dir = _avp_dir(sample.interface)
    if not avp_dir:
        return None
    name = _expected_filename(sample)
    if not name:
        return None
    path = os.path.join(avp_dir, name)
    return path if os.path.exists(path) else None


def load_spec_text(sample: Sample) -> Optional[str]:
    path = find_spec_doc(sample)
    if not path:
        return None
    try:
        return get_full_text(path)
    except Exception:
        return None
