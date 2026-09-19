#!/usr/bin/env bash
set -euo pipefail

# Section 6 / Table 18: LENS generalizability across 16 non-Diameter
# protocols (857 fields). BGP comprises core, EVPN, and FlowSpec components;
# D-Bus comprises bus-field and interface-method components.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

_BOOTSTRAP_PYTHON="${PYTHON:-}"
if [[ -z "${_BOOTSTRAP_PYTHON}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    _BOOTSTRAP_PYTHON=python3
  else
    _BOOTSTRAP_PYTHON=python
  fi
fi

echo "Preparing isolated project environment: .venv (dependencies install there; system Python unchanged)."
if [[ -e .venv ]]; then
  if [[ ! -f .venv/pyvenv.cfg ]]; then
    echo "Setup failed: .venv exists but is not a Python virtual environment. Move it aside and rerun." >&2
    exit 1
  fi
else
  if ! command -v "${_BOOTSTRAP_PYTHON}" >/dev/null 2>&1; then
    echo "Setup failed: Python executable '${_BOOTSTRAP_PYTHON}' was not found." >&2
    echo "Install Python 3.9+ or rerun with PYTHON pointing to a compatible interpreter." >&2
    exit 1
  fi
  if ! "${_BOOTSTRAP_PYTHON}" - <<'PY'
import sys

sys.exit(0 if sys.version_info >= (3, 9) else 1)
PY
  then
    echo "Setup failed: Python 3.9+ is required before creating .venv. Set PYTHON to a compatible interpreter and rerun." >&2
    exit 1
  fi
  echo "Creating project environment: .venv"
  if ! "${_BOOTSTRAP_PYTHON}" -m venv .venv; then
    echo "Setup failed: could not create .venv. Check permissions and Python venv support." >&2
    echo "On Ubuntu/Debian, install the matching python3-venv package, then rename any incomplete .venv and retry." >&2
    exit 1
  fi
fi
if [[ -x .venv/bin/python ]]; then
  PYTHON="${PWD}/.venv/bin/python"
elif [[ -x .venv/Scripts/python.exe ]]; then
  PYTHON="${PWD}/.venv/Scripts/python.exe"
else
  echo "Setup failed: .venv has no usable Python interpreter. Move it aside and rerun." >&2
  exit 1
fi
export PYTHON

if ! "${PYTHON}" - <<'PY'
import subprocess
import sys
from pathlib import Path

REQUIRED_PYTHON = (3, 9)
REQUIREMENTS = Path("requirements.txt")
DEPENDENCIES = (
    ("requests", "requests"),
    ("python-docx", "docx"),
    ("tiktoken", "tiktoken"),
)


def fail(message):
    print("Setup failed: " + message, file=sys.stderr)
    sys.exit(1)


def probe_dependencies(show_details=False):
    missing = []
    probe_code = (
        "import importlib, importlib.metadata, sys\n"
        "importlib.import_module(sys.argv[1])\n"
        "importlib.metadata.version(sys.argv[2])\n"
    )
    for package, module in DEPENDENCIES:
        probe = subprocess.run(
            [sys.executable, "-c", probe_code, module, package],
            capture_output=True,
            text=True,
        )
        if probe.returncode:
            missing.append(package)
            if show_details:
                detail = (probe.stderr or probe.stdout).strip().splitlines()
                print(f"  {package}: {detail[-1] if detail else 'import probe failed'}", file=sys.stderr)
    return missing


if sys.version_info < REQUIRED_PYTHON:
    fail(".venv uses Python " + sys.version.split()[0] + "; Python 3.9+ is required. Move .venv aside and rerun with a compatible PYTHON.")
if sys.prefix == sys.base_prefix:
    fail("expected to run inside the project .venv.")

missing = probe_dependencies()
if missing:
    print("Missing dependencies in .venv: " + ", ".join(missing), flush=True)
    if not REQUIREMENTS.is_file():
        fail("requirements.txt was not found; cannot install dependencies.")
    try:
        pip = subprocess.run([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if pip.returncode:
            print("pip is missing in .venv; attempting ensurepip.", flush=True)
            subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(REQUIREMENTS)], check=True)
    except (OSError, subprocess.CalledProcessError):
        fail("dependency installation in .venv failed. Check the pip error above and rerun; no experiment API calls were made.")
    remaining = probe_dependencies(show_details=True)
    if remaining:
        fail("dependencies still unavailable after installation: " + ", ".join(remaining) + ". Move .venv aside and rerun; no experiment API calls were made.")
else:
    print("Dependencies available in .venv.")
PY
then
  echo "Environment setup failed; no experiment API calls were made." >&2
  exit 1
fi
SERVICE="${SERVICE:-glm}"
WORKERS="${WORKERS:-7}"
ROUNDS="${ROUNDS:-3}"
PROTOCOLS="${PROTOCOLS:-mqtt}"
SUPPORTED_PROTOCOLS="sip bgp mqtt dhcp radius http2 dns snmp sle oci wayland modbus fuse rtsp amqp dbus"
read -r -a selected_protocols <<< "${PROTOCOLS}"
if [[ ${#selected_protocols[@]} -eq 0 ]]; then
  echo 'Specify protocols, e.g. PROTOCOLS="sip mqtt" bash scripts/run_generalizability.sh' >&2
  exit 2
fi
for protocol in "${selected_protocols[@]}"; do
  if [[ " ${SUPPORTED_PROTOCOLS} " != *" ${protocol} "* ]]; then
    echo "Unknown protocol: ${protocol}. Supported: ${SUPPORTED_PROTOCOLS}" >&2
    exit 2
  fi
done
PROTOCOLS="${selected_protocols[*]}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/generalizability}"

selected() {
  local protocol="$1"
  [[ " ${PROTOCOLS} " == *" ${protocol} "* ]]
}

run_component() {
  local paper_protocol="$1"
  local output_name="$2"
  local seed_name="$3"
  local protocol_id="$4"
  local target_name="$5"
  local attack_seed="$6"
  local safe_seed="$7"

  if ! selected "${paper_protocol}"; then
    return
  fi

  "${PYTHON}" -m src.generalizability \
    --service "${SERVICE}" \
    --seed-examples "data/non_diameter/seed/${seed_name}.md" \
    --attack-indices "${attack_seed}" \
    --safe-indices "${safe_seed}" \
    --attack-side all \
    --rounds "${ROUNDS}" \
    --workers "${WORKERS}" \
    --target-paths-file "data/non_diameter/target/${target_name}" \
    --target-side all \
    --protocol "${protocol_id}" \
    --output-dir "${OUTPUT_ROOT}/${output_name}"
}

run_component sip sip sip sip sip_header_targets.json 1 5

run_component bgp bgp/core bgp bgp bgp_attribute_targets.json 1 7
run_component bgp bgp/evpn bgp_evpn bgp_evpn bgp_evpn_targets.json 1 7
run_component bgp bgp/flowspec bgp_flowspec bgp_flowspec bgp_flowspec_targets.json 1 7

run_component mqtt mqtt mqtt mqtt mqtt_v5_field_targets.json 1 5
run_component dhcp dhcp dhcp dhcp dhcp_option_targets.json 1 5
run_component radius radius radius radius radius_attribute_targets.json 1 5
run_component http2 http2 http2 http2 http2_frame_targets.json 1 5
run_component dns dns dns dns dns_rr_targets.json 1 5
run_component snmp snmp snmp snmp snmp_binding_targets.json 1 5
run_component sle sle sle sle sle_parameter_targets.json 1 4
run_component oci oci oci oci oci_setting_targets.json 1 5
run_component wayland wayland wayland wayland wayland_argument_targets.json 1 5
run_component modbus modbus modbus modbus modbus_register_targets.json 1 5
run_component fuse fuse fuse fuse fuse_field_targets.json 1 5
run_component rtsp rtsp rtsp rtsp rtsp_targets.json 1 6
run_component amqp amqp amqp amqp amqp_field_targets.json 1 2

run_component dbus dbus/bus_fields dbus dbus dbus_bus_field_targets_v2.json 1 6
run_component dbus dbus/methods dbus dbus dbus_method_targets.json 1 6
