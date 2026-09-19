from __future__ import annotations

import itertools
import csv
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .parsing import _normalize_label


@dataclass
class Sample:
    number: int
    title: str
    label: str
    message_full: str
    message_abbr: str
    target_path: str
    target_type: str
    content: str
    interface: str
    input_key: str = ""
    source: str = "training"

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SupportSet:
    support_id: str
    sample_count: int
    attacks: List[Sample]
    safes: List[Sample]

    @property
    def samples(self) -> List[Sample]:
        return [*self.attacks, *self.safes]

    def to_dict(self) -> Dict:
        return {
            "support_id": self.support_id,
            "sample_count": self.sample_count,
            "attacks": [s.to_dict() for s in self.attacks],
            "safes": [s.to_dict() for s in self.safes],
        }


_DIAMETER_INTERFACES = {"s6a", "s6d", "cx", "sh"}

_PROTOCOL_META = {
    "s6a": {"protocol": "Diameter", "target_type": "AVP", "message_key": "message"},
    "s6d": {"protocol": "Diameter", "target_type": "AVP", "message_key": "message"},
    "cx": {"protocol": "Diameter", "target_type": "AVP", "message_key": "message"},
    "sh": {"protocol": "Diameter", "target_type": "AVP", "message_key": "message"},
    "n1": {"protocol": "5G-NAS", "target_type": "IE", "message_key": "message"},
    "sip": {"protocol": "SIP", "target_type": "Header", "message_key": "method"},
    "mqtt": {"protocol": "MQTT", "target_type": "Field", "message_key": "message"},
    "coap": {"protocol": "CoAP", "target_type": "Option", "message_key": "method"},
    "oci": {"protocol": "OCI", "target_type": "Setting", "message_key": "section"},
    "sle": {"protocol": "CCSDS-SLE", "target_type": "Parameter", "message_key": "operation"},
    "tc": {"protocol": "CCSDS-TC/SDLS", "target_type": "Element", "message_key": "frame_type"},
    "wayland": {"protocol": "Wayland", "target_type": "Argument", "message_key": "request"},
    "amqp": {"protocol": "AMQP", "target_type": "Performative-Field", "message_key": "performative"},
    "bacnet": {"protocol": "BACnet", "target_type": "Property", "message_key": "service"},
    "bgp": {"protocol": "BGP", "target_type": "Attribute", "message_key": "message_type"},
    "bgp_evpn": {"protocol": "BGP EVPN", "target_type": "Attribute", "message_key": "message_type"},
    "bgp_flowspec": {"protocol": "BGP FlowSpec", "target_type": "Attribute", "message_key": "message_type"},
    "cwmp": {"protocol": "CWMP/TR-069", "target_type": "Parameter", "message_key": "rpc_method"},
    "dbus": {"protocol": "D-Bus", "target_type": "Bus Field", "message_key": "message_type"},
    "dhcp": {"protocol": "DHCP", "target_type": "Option", "message_key": "message_type"},
    "dns": {"protocol": "DNS", "target_type": "RR", "message_key": "message_type"},
    "fuse": {"protocol": "FUSE", "target_type": "Operation Field", "message_key": "message_type"},
    "http2": {"protocol": "HTTP/2", "target_type": "Frame", "message_key": "frame_type"},
    "modbus": {"protocol": "Modbus", "target_type": "Register", "message_key": "function_code"},
    "radius": {"protocol": "RADIUS", "target_type": "Attribute", "message_key": "packet_type"},
    "rtsp": {"protocol": "RTSP", "target_type": "Header", "message_key": "method"},
    "snmp": {"protocol": "SNMP", "target_type": "Binding", "message_key": "pdu_type"},
    "tls13": {"protocol": "TLS 1.3", "target_type": "Extension", "message_key": "message_type"},
}

_PROTOCOL_ALIASES = {
    "diameter-s6a": "s6a",
    "diameter_s6a": "s6a",
    "diameter-cx": "cx",
    "diameter_cx": "cx",
    "diameter-sh": "sh",
    "diameter_sh": "sh",
    "diameter": "",
    "nas": "n1",
    "5g-nas": "n1",
    "5g_nas": "n1",
    "n1": "n1",
    "sip": "sip",
    "mqtt": "mqtt",
    "mqtt-v5": "mqtt",
    "mqtt_v5": "mqtt",
    "coap": "coap",
    "oci": "oci",
    "sle": "sle",
    "tc": "tc",
    "wayland": "wayland",
    "amqp": "amqp",
    "bacnet": "bacnet",
    "bgp": "bgp",
    "bgp-evpn": "bgp_evpn",
    "bgp_evpn": "bgp_evpn",
    "evpn": "bgp_evpn",
    "bgp-flowspec": "bgp_flowspec",
    "bgp_flowspec": "bgp_flowspec",
    "flowspec": "bgp_flowspec",
    "cwmp": "cwmp",
    "tr069": "cwmp",
    "tr-069": "cwmp",
    "dbus": "dbus",
    "d-bus": "dbus",
    "dhcp": "dhcp",
    "dns": "dns",
    "fuse": "fuse",
    "http2": "http2",
    "http-2": "http2",
    "http_2": "http2",
    "modbus": "modbus",
    "radius": "radius",
    "rtsp": "rtsp",
    "snmp": "snmp",
    "tls13": "tls13",
    "tls-1.3": "tls13",
    "tls_1_3": "tls13",
}

_FILENAME_INTERFACE_PREFIXES = {
    "bgp_flowspec": "bgp_flowspec",
    "bgp_evpn": "bgp_evpn",
    "mqtt_v5": "mqtt",
    "dbus_bus_field": "dbus",
    "dbus_method": "dbus",
    **{key: value for key, value in _PROTOCOL_ALIASES.items() if value},
}

_FILENAME_TARGET_TYPE_PREFIXES = {
    "amqp_field": "Performative-Field",
    "bacnet_property": "Property",
    "bgp_attribute": "Attribute",
    "bgp_evpn": "Attribute",
    "bgp_flowspec": "Attribute",
    "coap_option": "Option",
    "cwmp_parameter": "Parameter",
    "dbus_bus_field": "Bus Field",
    "dbus_method": "Interface Method",
    "dhcp_option": "Option",
    "dns_rr": "RR",
    "fuse_field": "Operation Field",
    "http2_frame": "Frame",
    "modbus_register": "Register",
    "mqtt_v5_field": "Field",
    "oci_setting": "Setting",
    "radius_attribute": "Attribute",
    "sip_header": "Header",
    "sle_parameter": "Parameter",
    "snmp_binding": "Binding",
    "tc_element": "Element",
    "tls13": "Extension",
    "wayland_argument": "Argument",
}

_TARGET_TYPE_ALIASES = {
    "diameter field": "AVP",
    "diameter field path": "AVP",
    "diameter-field": "AVP",
    "diameter-field-path": "AVP",
    "performative field": "Performative-Field",
    "performative-field": "Performative-Field",
    "bus field": "Bus Field",
    "bus-field": "Bus Field",
    "frame field": "Frame-Field",
    "frame-field": "Frame-Field",
    "interface method": "Interface Method",
    "interface-method": "Interface Method",
    "rr": "RR",
    "resource record": "RR",
    "op": "Operation Field",
    "operation field": "Operation Field",
    "operation-field": "Operation Field",
}

_CSV_TARGET_COLUMNS = [
    ("AVP", "avp_path"),
    ("IE", "ie_path"),
    ("Header", "header_path"),
    ("Header", "header"),
    ("Field", "field_path"),
    ("Field", "field"),
    ("Option", "option_path"),
    ("Option", "option"),
    ("Setting", "setting_path"),
    ("Setting", "setting"),
    ("Parameter", "parameter_path"),
    ("Parameter", "parameter"),
    ("Element", "element_path"),
    ("Element", "element"),
    ("Argument", "argument_path"),
    ("Argument", "argument"),
    ("Property", "property_path"),
    ("Property", "property"),
    ("Attribute", "attribute_path"),
    ("Attribute", "attribute"),
    ("Register", "register_path"),
    ("Register", "register"),
    ("Binding", "binding_path"),
    ("Binding", "binding"),
    ("Extension", "extension_path"),
    ("Extension", "extension"),
    ("RR", "rr_path"),
    ("RR", "rr_field"),
    ("Op", "op_path"),
    ("Op", "op"),
    ("Operation Field", "operation_field_path"),
    ("Operation Field", "operation_field"),
    ("Bus Field", "bus_field_path"),
    ("Bus Field", "bus_field"),
    ("Frame-Field", "frame_field_path"),
    ("Frame-Field", "frame_field"),
    ("Performative-Field", "performative_field_path"),
    ("Performative-Field", "performative_field"),
    ("Method", "method_path"),
    ("Interface Method", "interface_method_path"),
    ("Interface Method", "interface_method"),
]

_JSON_TARGET_KEYS_BY_TYPE = {
    "AVP": ["avp_path", "avp", "target_path"],
    "IE": ["ie_path", "ie", "target_path"],
    "Header": ["header_path", "header", "target_path"],
    "Field": ["field_path", "field", "target_path"],
    "Option": ["option_path", "option", "dhcp_field", "target_path"],
    "Setting": ["setting_path", "setting", "target_path"],
    "Parameter": ["parameter_path", "parameter", "target_path"],
    "Element": ["element_path", "element", "target_path"],
    "Argument": ["argument_path", "argument", "target_path"],
    "Property": ["property_path", "property", "target_path"],
    "Attribute": ["attribute_path", "attribute", "target_path"],
    "Register": ["register_path", "register", "target_path"],
    "Binding": ["binding_path", "binding", "target_path"],
    "Extension": ["extension_path", "extension", "target_path"],
    "RR": ["rr_path", "rr_field", "target_path"],
    "Op": ["op_path", "op", "field", "target_path"],
    "Operation Field": ["operation_field_path", "operation_field", "op_path", "op", "field", "target_path"],
    "Frame": ["frame_path", "frame", "field", "target_path"],
    "Bus Field": ["bus_field_path", "bus_field", "target_path"],
    "Frame-Field": ["frame_field_path", "frame_field", "field", "target_path"],
    "Performative-Field": ["performative_field_path", "performative_field", "field", "target_path"],
    "Method": ["method_path", "method", "target_path"],
    "Interface Method": ["interface_method_path", "interface_method", "method_path", "method", "target_path"],
}

_JSON_MESSAGE_KEYS = [
    "message",
    "message_full",
    "message_type",
    "method",
    "request",
    "operation",
    "service",
    "section",
    "function_code",
    "packet_type",
    "pdu_type",
    "frame_type",
    "rpc_method",
    "performative",
]


def parse_seed_examples(path: str, label: Optional[str] = None, attack_side: str = "all") -> List[Sample]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    default_interface = _interface_from_path(path)
    samples = []
    for part in re.split(r"(?=^## \d+\))", text, flags=re.MULTILINE):
        part = part.strip()
        if not part:
            continue

        header = re.match(r"^## (\d+)\)\s+(.+)", part)
        if not header:
            continue
        number = int(header.group(1))
        title = header.group(2).strip()

        msg_match = re.search(r"\*\*Message:\*\*\s*(.+)", part)
        if not msg_match:
            continue
        message_full, message_abbr = _parse_message(msg_match.group(1).strip())

        target_type, target_path = _target_from_seed_example(part)

        cls_match = re.search(
            r"\*\*Classification:\*\*\s*(?:\n\s*)?([A-Za-z][A-Za-z\s_-]*)",
            part,
        )
        classification = _normalize_label(cls_match.group(1)) if cls_match else "UNKNOWN"
        requested_label = _normalize_label(label) if label else None
        if requested_label and classification != requested_label:
            continue

        content_match = re.search(r"(\*\*Threat Model:\*\*.*)", part, re.DOTALL)
        content = content_match.group(1).strip() if content_match else part
        protocol_match = re.search(r"\*\*(?:Protocol|Interface):\*\*\s*(.+)", part)
        explicit_interface = (
            _protocol_to_interface(protocol_match.group(1).strip())
            if protocol_match
            else ""
        )
        interface = explicit_interface or default_interface or message_to_interface(message_full, target_type)

        sample = Sample(
            number=number,
            title=f"{number}) {title}",
            label=classification,
            message_full=message_full,
            message_abbr=message_abbr,
            target_path=target_path,
            target_type=target_type,
            content=content,
            interface=interface,
            input_key=f"case{number:02d}",
        )
        samples.append(sample)

    if label and _normalize_label(label) == "ATTACK":
        samples = filter_attack_side(samples, attack_side)
    return samples


def filter_attack_side(samples: List[Sample], attack_side: str) -> List[Sample]:
    if attack_side == "all":
        return samples
    if attack_side == "request":
        return [
            s
            for s in samples
            if s.message_full.endswith("Request") or s.interface not in {"s6a", "cx", "sh"}
        ]
    if attack_side == "answer":
        return [s for s in samples if s.message_full.endswith("Answer")]
    return samples


def build_minimal_input(sample: Sample) -> str:
    iface = sample.interface.lower()
    meta = _PROTOCOL_META.get(iface)
    protocol = meta["protocol"] if meta else (sample.interface or "Unknown")
    default_target_type = meta["target_type"] if meta else "Field"
    field_label = _normalize_target_type(sample.target_type or default_target_type)
    is_diameter_field = protocol == "Diameter" and field_label == "AVP"
    display_label = "Diameter Field" if is_diameter_field else field_label
    path_key = "diameter field" if is_diameter_field else _path_key_for_target_type(field_label)
    message_key = meta["message_key"] if meta else "message"
    if field_label == "Frame-Field":
        message_key = "frame_type"
    interface_value = sample.interface.upper() if iface in _DIAMETER_INTERFACES | {"n1"} else protocol
    return (
        f"=== Target {display_label} Information ===\n"
        f'  protocol: "{protocol}"\n'
        f'  interface: "{interface_value}"\n'
        f'  {message_key}: "{sample.message_full}"\n'
        f'  {path_key}: "{sample.target_path}"\n'
    )


def build_input_for_case(sample: Sample, input_override_dir: str = None) -> str:
    base = build_minimal_input(sample)
    if not input_override_dir:
        return base
    path = os.path.join(input_override_dir, f"{sample.input_key}_input.txt")
    if not os.path.exists(path):
        return base
    with open(path, "r", encoding="utf-8") as f:
        context = f.read().strip()
    if not context:
        return base
    return f"{base.rstrip()}\n\n===Protocol Evidence===\n{context}\n"


def select_support_sets(
    attacks: List[Sample],
    safes: List[Sample],
    sample_counts: Sequence[int],
    attack_indices: Optional[Sequence[int]] = None,
    safe_indices: Optional[Sequence[int]] = None,
    max_sets_per_count: int = 1,
    safe_mode: str = "matched",
) -> List[SupportSet]:
    attack_map = {s.number: s for s in attacks}
    safe_map = {s.number: s for s in safes}
    attack_pool = _select_by_indices(attacks, attack_indices, attack_map)
    safe_pool = _select_by_indices(safes, safe_indices, safe_map)
    support_sets = []

    for count in sample_counts:
        if count < 1:
            continue
        if attack_indices:
            attack_combos = [tuple(attack_pool[:count])] if len(attack_pool) >= count else []
        else:
            attack_combos = itertools.islice(itertools.combinations(attack_pool, count), max_sets_per_count)

        for attack_combo in attack_combos:
            safe_combo = _pick_safe_samples(
                list(attack_combo), safe_pool, safe_map, count, safe_indices is not None, safe_mode
            )
            if len(safe_combo) != count:
                continue
            attack_ids = "-".join(f"{s.number:02d}" for s in attack_combo)
            safe_ids = "-".join(f"{s.number:02d}" for s in safe_combo)
            support_sets.append(
                SupportSet(
                    support_id=f"m{count:02d}_a{attack_ids}_s{safe_ids}",
                    sample_count=count,
                    attacks=list(attack_combo),
                    safes=safe_combo,
                )
            )
    return support_sets


def parse_index_list(raw: str) -> Optional[List[int]]:
    if not raw:
        return None
    return [int(x.strip()) for x in raw.split(",") if x.strip()]


def load_avp_paths_file(path: str, message_side: str = "all") -> List[Sample]:
    samples = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z\-]+):\s*(.+)$", line)
            if not match:
                continue
            message_full = match.group(1).strip()
            if message_side == "request" and not message_full.endswith("Request"):
                continue
            if message_side == "answer" and not message_full.endswith("Answer"):
                continue
            target_path = match.group(2).strip()
            _, message_abbr = _parse_message(message_full)
            samples.append(
                Sample(
                    number=100000 + i,
                    title=f"eval) {message_full} - {target_path}",
                    label="UNKNOWN",
                    message_full=message_full,
                    message_abbr=message_abbr,
                    target_path=target_path,
                    target_type="AVP",
                    content="",
                    interface=message_to_interface(message_full, "AVP"),
                    input_key=f"eval{i:05d}_{message_abbr}_{_safe_name(target_path)}",
                    source="avp_paths",
                )
            )
    return samples


def load_labeled_targets_file(path: str, message_side: str = "all") -> List[Sample]:
    samples = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, 1):
            message_full = (row.get("message") or row.get("message_full") or "").strip()
            target_type, target_path = _target_from_row(row)
            if not message_full or not target_path:
                continue
            if message_side == "request" and not message_full.endswith("Request"):
                continue
            if message_side == "answer" and not message_full.endswith("Answer"):
                continue

            _, message_abbr = _parse_message(message_full)
            label = (row.get("label") or "UNKNOWN").strip().upper()
            interface = (row.get("iface") or row.get("interface") or "").strip().lower()
            if not interface:
                interface = message_to_interface(message_full, target_type)
            number = int(row["number"]) if (row.get("number") or "").strip() else 200000 + i
            input_key = (row.get("input_key") or "").strip() or f"val{i:03d}"
            samples.append(
                Sample(
                    number=number,
                    title=f"evaluation) {message_full} - {target_path}",
                    label=label,
                    message_full=message_full,
                    message_abbr=message_abbr,
                    target_path=target_path,
                    target_type=target_type,
                    content="",
                    interface=interface,
                    input_key=input_key,
                    source="evaluation_dataset",
                )
            )
    return samples


def load_target_paths_file(
    path: str,
    message_side: str = "all",
    protocol: str = None,
    target_type: str = None,
) -> List[Sample]:
    if path.lower().endswith(".csv"):
        samples = load_labeled_targets_file(path, message_side=message_side)
    elif path.lower().endswith(".json"):
        samples = _load_json_target_paths_file(
            path,
            message_side=message_side,
            protocol=protocol,
            target_type=target_type,
        )
    else:
        samples = _load_text_target_paths_file(
            path,
            message_side=message_side,
            protocol=protocol,
            target_type=target_type,
        )
    if protocol:
        interface = _protocol_to_interface(protocol)
        if interface:
            samples = [
                Sample(**{**s.to_dict(), "interface": interface})
                for s in samples
            ]
    if target_type:
        target_type = _normalize_target_type(target_type)
        samples = [
            Sample(**{**s.to_dict(), "target_type": target_type})
            for s in samples
        ]
    return samples


def message_to_interface(message_full: str, target_type: str = "") -> str:
    type_map = {
        "IE": "n1",
        "Header": "sip",
        "Field": "mqtt",
        "Option": "coap",
        "Setting": "oci",
        "Parameter": "sle",
        "Element": "tc",
        "Argument": "wayland",
        "Performative-Field": "amqp",
        "Property": "bacnet",
        "Register": "modbus",
        "Binding": "snmp",
        "Extension": "tls13",
        "RR": "dns",
        "Op": "fuse",
        "Operation Field": "fuse",
        "Bus Field": "dbus",
        "Frame-Field": "amqp",
        "Interface Method": "dbus",
    }
    target_type = _normalize_target_type(target_type)
    if target_type in type_map:
        return type_map[target_type]

    for prefix in [
        "Authentication-Information",
        "Update-Location",
        "Cancel-Location",
        "Insert-Subscriber-Data",
        "Delete-Subscriber-Data",
        "Purge-UE",
        "Notify",
        "Reset",
    ]:
        if message_full.startswith(prefix):
            return "s6a"
    for prefix in [
        "Location-Info",
        "Multimedia-Auth",
        "Server-Assignment",
        "User-Authorization",
        "Registration-Termination",
        "Push-Profile",
    ]:
        if message_full.startswith(prefix):
            return "cx"
    for prefix in ["Subscribe-Notifications", "Push-Notification", "User-Data", "Profile-Update"]:
        if message_full.startswith(prefix):
            return "sh"
    return "unknown"


def _parse_message(raw: str) -> tuple[str, str]:
    match = re.match(r"([A-Za-z\-]+)\s*\(([A-Z0-9_]+)\)", raw)
    if match:
        return match.group(1).strip(), match.group(2).strip()
    abbr_map = {
        "Authentication-Information-Request": "AIR",
        "Authentication-Information-Answer": "AIA",
        "Update-Location-Request": "ULR",
        "Update-Location-Answer": "ULA",
        "Cancel-Location-Request": "CLR",
        "Cancel-Location-Answer": "CLA",
        "Insert-Subscriber-Data-Request": "IDR",
        "Insert-Subscriber-Data-Answer": "IDA",
        "Delete-Subscriber-Data-Request": "DSR",
        "Delete-Subscriber-Data-Answer": "DSA",
        "Purge-UE-Request": "PUR",
        "Purge-UE-Answer": "PUA",
        "Notify-Request": "NOR",
        "Notify-Answer": "NOA",
        "Reset-Request": "RSR",
        "Reset-Answer": "RSA",
        "Location-Info-Request": "LIR",
        "Location-Info-Answer": "LIA",
        "Multimedia-Auth-Request": "MAR",
        "Multimedia-Auth-Answer": "MAA",
        "Server-Assignment-Request": "SAR",
        "Server-Assignment-Answer": "SAA",
        "User-Authorization-Request": "UAR",
        "User-Authorization-Answer": "UAA",
        "Registration-Termination-Request": "RTR",
        "Registration-Termination-Answer": "RTA",
        "Push-Profile-Request": "PPR",
        "Push-Profile-Answer": "PPA",
        "User-Data-Request": "UDR",
        "User-Data-Answer": "UDA",
    }
    if raw in abbr_map:
        return raw, abbr_map[raw]
    return raw, "".join(part[0].upper() for part in re.split(r"[-_.\s]+", raw) if part)


def _target_from_row(row: Dict[str, str]) -> tuple[str, str]:
    explicit_type = _normalize_target_type((row.get("target_type") or row.get("field_type") or "").strip())
    for candidate_type, column in _CSV_TARGET_COLUMNS:
        value = (row.get(column) or "").strip()
        if value:
            return explicit_type or candidate_type, value
    return explicit_type or "AVP", (row.get("target_path") or "").strip()


def _load_json_target_paths_file(
    path: str,
    message_side: str,
    protocol: str = None,
    target_type: str = None,
) -> List[Sample]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    records = payload.get("targets", []) if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        return []

    inferred_interface = _protocol_to_interface(protocol or "") or _interface_from_path(path)
    source_name = _safe_name(os.path.splitext(os.path.basename(path))[0]) or "json_targets"

    samples: List[Sample] = []
    for i, row in enumerate(records, 1):
        if not isinstance(row, dict):
            continue

        row_interface = _protocol_to_interface(
            str(row.get("protocol") or row.get("iface") or row.get("interface") or "")
        )
        interface = row_interface or inferred_interface
        field_type = (
            _normalize_target_type(target_type or "")
            or _normalize_target_type(str(row.get("target_type") or row.get("field_type") or ""))
            or _target_type_from_path(path)
            or _target_type_for_interface(interface)
            or _target_type_from_json_record(row)
            or "Field"
        )
        target_path = _target_path_from_json_record(row, field_type)
        message_full = _message_from_json_record(row, interface)
        if not message_full or not target_path:
            continue
        if message_side == "request" and message_full.endswith("Answer"):
            continue
        if message_side == "answer" and message_full.endswith("Request"):
            continue

        _, message_abbr = _parse_message(message_full)
        samples.append(
            Sample(
                number=300000 + i,
                title=f"target) {message_full} - {target_path}",
                label=str(row.get("label") or "UNKNOWN").strip().upper(),
                message_full=message_full,
                message_abbr=message_abbr,
                target_path=target_path,
                target_type=field_type,
                content="",
                interface=interface or message_to_interface(message_full, field_type),
                input_key=_build_input_key("target", i, message_abbr, target_path),
                source=source_name,
            )
        )
    return samples


def _load_text_target_paths_file(
    path: str,
    message_side: str,
    protocol: str = None,
    target_type: str = None,
) -> List[Sample]:
    samples = []
    default_interface = _protocol_to_interface(protocol or "")
    default_target_type = target_type or _target_type_for_interface(default_interface)
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([^:]+):\s*(.+)$", line)
            if not match:
                continue
            message_full = match.group(1).strip()
            if message_side == "request" and not message_full.endswith("Request"):
                continue
            if message_side == "answer" and not message_full.endswith("Answer"):
                continue
            target_path = match.group(2).strip()
            field_type = default_target_type or "AVP"
            interface = default_interface or message_to_interface(message_full, field_type)
            _, message_abbr = _parse_message(message_full)
            samples.append(
                Sample(
                    number=300000 + i,
                    title=f"target) {message_full} - {target_path}",
                    label="UNKNOWN",
                    message_full=message_full,
                    message_abbr=message_abbr,
                    target_path=target_path,
                    target_type=field_type,
                    content="",
                    interface=interface,
                    input_key=_build_input_key("target", i, message_abbr, target_path),
                    source="target_paths",
                )
            )
    return samples


def _protocol_to_interface(protocol: str) -> str:
    raw = (protocol or "").strip().lower()
    return _PROTOCOL_ALIASES.get(raw, raw)


def _target_type_for_interface(interface: str) -> str:
    meta = _PROTOCOL_META.get((interface or "").lower())
    return meta["target_type"] if meta else ""


def _interface_from_path(path: str) -> str:
    stem = os.path.splitext(os.path.basename(path))[0].lower().replace("-", "_")
    for prefix, interface in sorted(_FILENAME_INTERFACE_PREFIXES.items(), key=lambda item: len(item[0]), reverse=True):
        normalized = prefix.replace("-", "_")
        if stem == normalized or stem.startswith(f"{normalized}_"):
            return interface
    return ""


def _target_type_from_path(path: str) -> str:
    stem = os.path.splitext(os.path.basename(path))[0].lower().replace("-", "_")
    for prefix, target_type in sorted(_FILENAME_TARGET_TYPE_PREFIXES.items(), key=lambda item: len(item[0]), reverse=True):
        if stem == prefix or stem.startswith(f"{prefix}_"):
            return target_type
    return ""


def _normalize_target_type(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return ""
    compact = re.sub(r"\s+", " ", value.replace("_", " ")).strip()
    return _TARGET_TYPE_ALIASES.get(compact.lower(), compact)


def _target_from_seed_example(part: str) -> tuple[str, str]:
    possessive_match = re.search(r"\*\*Target\s+(.+?)'s path:\*\*\s*(.+)", part)
    if possessive_match:
        return _normalize_target_type(possessive_match.group(1)), possessive_match.group(2).strip()

    target_match = re.search(r"\*\*Target\s+(.+?):\*\*\s*(.+)", part)
    if target_match:
        return _normalize_target_type(target_match.group(1)), target_match.group(2).strip()

    return "AVP", ""


def _path_key_for_target_type(target_type: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", target_type).strip("_").lower()
    if normalized.endswith("_path"):
        return normalized
    return f"{normalized or 'target'}_path"


def _target_type_from_json_record(row: Dict) -> str:
    for candidate_type, key in _CSV_TARGET_COLUMNS:
        if str(row.get(key) or "").strip():
            return candidate_type
    for candidate_type, keys in _JSON_TARGET_KEYS_BY_TYPE.items():
        if any(str(row.get(key) or "").strip() for key in keys):
            return candidate_type
    return ""


def _target_path_from_json_record(row: Dict, target_type: str) -> str:
    keys = _JSON_TARGET_KEYS_BY_TYPE.get(_normalize_target_type(target_type), [])
    fallback_keys = [key for _, key in _CSV_TARGET_COLUMNS] + [
        "target_path",
        "field",
        "dhcp_field",
        "rr_field",
        "bus_field",
        "method",
    ]
    for key in [*keys, *fallback_keys]:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _message_from_json_record(row: Dict, interface: str) -> str:
    meta = _PROTOCOL_META.get((interface or "").lower(), {})
    preferred = meta.get("message_key")
    keys = [preferred] if preferred else []
    keys.extend(key for key in _JSON_MESSAGE_KEYS if key not in keys)
    for key in keys:
        value = row.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return (interface or "target").upper()


def _select_by_indices(pool: List[Sample], indices: Optional[Sequence[int]], mapping: Dict[int, Sample]) -> List[Sample]:
    if not indices:
        return pool
    return [mapping[i] for i in indices if i in mapping]


def _pick_safe_samples(
    attacks: List[Sample],
    safe_pool: List[Sample],
    safe_map: Dict[int, Sample],
    count: int,
    explicit_safe: bool,
    safe_mode: str,
) -> List[Sample]:
    if explicit_safe or safe_mode == "first":
        return safe_pool[:count]

    selected = []
    used = set()
    for attack in attacks:
        candidate = safe_map.get(attack.number + 10)
        if candidate and candidate.number not in used:
            selected.append(candidate)
            used.add(candidate.number)

    for sample in safe_pool:
        if len(selected) >= count:
            break
        if sample.number not in used:
            selected.append(sample)
            used.add(sample.number)
    return selected[:count]


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", text.replace(".", "_")).strip("_")


def _build_input_key(prefix: str, index: int, message_abbr: str, target_path: str, max_len: int = 96) -> str:
    safe_msg = _safe_name(message_abbr) or "msg"
    safe_target = _safe_name(target_path) or "target"
    base = f"{prefix}{index:05d}_{safe_msg}_{safe_target}"
    if len(base) <= max_len:
        return base
    digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:10]
    head = f"{prefix}{index:05d}_{safe_msg[:12].rstrip('_')}_"
    remaining = max(12, max_len - len(head) - len(digest) - 1)
    return f"{head}{safe_target[:remaining].rstrip('_')}_{digest}"
