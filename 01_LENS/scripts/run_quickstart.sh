#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ $# -gt 0 ]]; then
  echo "Usage: bash scripts/run_quickstart.sh" >&2
  echo "Run this command without arguments from the Artifact directory." >&2
  exit 2
fi
if [[ -z "${PYTHON:-}" ]]; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
  else
    PYTHON=python
  fi
fi
export SERVICE="${SERVICE:-glm}"
export OUTPUT_ROOT="${OUTPUT_ROOT:-output/quickstart}"
if ! command -v "${PYTHON}" >/dev/null 2>&1; then
  echo "Setup check failed: Python executable '${PYTHON}' was not found." >&2
  echo "Install Python 3.9+, activate your environment, or use PYTHON=python3 bash scripts/run_quickstart.sh." >&2
  exit 1
fi

echo "LENS quick start"
echo "Creates or reuses an isolated .venv here (system Python untouched), installs deps, then runs one live example."
echo "Needs Internet; API charges may apply."
echo "[1/2] Preparing your setup..."
if [[ -e .venv ]]; then
  if [[ ! -f .venv/pyvenv.cfg ]]; then
    echo "Setup failed: .venv exists but is not a Python virtual environment. Move it aside and rerun." >&2
    exit 1
  fi
else
  if ! "${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "Setup failed: Python 3.9+ is required. Select a compatible interpreter using PYTHON and rerun." >&2
    exit 1
  fi
  echo "Creating project environment: .venv"
  if ! "${PYTHON}" -m venv .venv; then
    echo "Could not create .venv. Check directory permissions and Python venv support." >&2
    echo "On Ubuntu/Debian, install the matching python3-venv package, then rename any incomplete .venv and retry." >&2
    exit 1
  fi
fi
if [[ -x .venv/bin/python ]]; then
  PYTHON="${PWD}/.venv/bin/python"
elif [[ -x .venv/Scripts/python.exe ]]; then
  PYTHON="${PWD}/.venv/Scripts/python.exe"
else
  echo "Setup failed: .venv has no usable Python. Rename .venv and rerun to create it for this platform." >&2
  exit 1
fi
export PYTHON
"${PYTHON}" - <<'PY'
import sys

if sys.version_info < (3, 9):
    print("Setup check failed: Python 3.9 or newer is required.\n  Install Python 3.9+, activate that environment, and rerun this script.", file=sys.stderr)
    sys.exit(1)

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

CONFIG = Path("config/api_config.json")
RESTORE = (
    "  You may not have replaced the configuration correctly.\n"
    "  Copy reviewer_config.json from HotCRP over config/api_config.json, then rerun."
)


def fail(message):
    print("Setup check failed: " + message, file=sys.stderr)
    sys.exit(1)


def technical_detail(exc):
    detail = str(exc)
    detail = re.sub(r"sk-[A-Za-z0-9_-]+", "[REDACTED]", detail)
    detail = re.sub(r"(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", detail)
    print(f"  Technical detail: {type(exc).__name__}: {detail}", file=sys.stderr)


def check_dependencies(show_details=False):
    problems = []
    for package, module in [
        ("requests", "requests"),
        ("python-docx", "docx"),
        ("tiktoken", "tiktoken"),
    ]:
        probe = subprocess.run(
            [sys.executable, "-c",
             "import importlib, importlib.metadata, sys; "
             "importlib.import_module(sys.argv[1]); "
             "print(importlib.metadata.version(sys.argv[2]))", module, package],
            capture_output=True, text=True,
        )
        if probe.returncode:
            problems.append(package)
            if show_details:
                technical_detail(RuntimeError(f"{package}: {probe.stderr.strip()}"))
            elif f"No module named '{module}'" in probe.stderr:
                print(f"  Missing: {package} (will install automatically)")
            else:
                print(f"  Unavailable: {package} (will attempt dependency installation)")
        else:
            print(f"  OK: {package} {probe.stdout.strip()}")
    return problems


def check():
    if sys.prefix == sys.base_prefix:
        fail("Expected the project virtual environment. Rerun using scripts/run_quickstart.sh.")
    print("  OK: Python " + sys.version.split()[0] + " (.venv)")
    missing = check_dependencies()
    if missing:
        print("Installing dependencies into .venv: " + ", ".join(missing), flush=True)
        try:
            pip = subprocess.run([sys.executable, "-m", "pip", "--version"],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if pip.returncode:
                subprocess.run([sys.executable, "-m", "ensurepip", "--upgrade"], check=True)
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            technical_detail(exc)
            fail("Dependency installation in .venv failed.\n"
                 "  Check the installation error above, your Internet/proxy settings, and write permissions.\n"
                 "  Fix the issue and rerun this script; no model API calls have been made.")
        remaining = check_dependencies(show_details=True)
        if remaining:
            fail("Dependencies still cannot be used: " + ", ".join(remaining) + ".\n"
                 "  Rename .venv and rerun to create a clean environment. Your existing files will not be deleted.")

    try:
        with CONFIG.open(encoding="utf-8-sig") as handle:
            config = json.load(handle)
    except FileNotFoundError:
        fail(f"{CONFIG.as_posix()} was not found.\n{RESTORE}")
    except (json.JSONDecodeError, UnicodeError):
        fail(f"{CONFIG.as_posix()} is not valid UTF-8 JSON.\n{RESTORE}")
    except OSError:
        fail(f"Cannot read {CONFIG.as_posix()}.\n"
             "  Make sure your account can read this file.\n" + RESTORE)

    service = os.environ["SERVICE"]
    if not isinstance(config, dict):
        fail(f"{CONFIG.as_posix()} must contain a JSON object of services.\n{RESTORE}")
    entry = config.get(service)
    if not isinstance(entry, dict):
        fail(f'No configuration found for service "{service}" in {CONFIG.as_posix()}.\n'
             f'{RESTORE}\n  Or set SERVICE to a service name present in that file.')

    def invalid(field, detail):
        fail(f'The configuration for "{service}" in {CONFIG.as_posix()} is incomplete '
             f'(missing/invalid: {field}).\n{RESTORE}\n  Details: {detail}')

    if entry.get("type") not in ("openai", "openai_compatible", "anthropic", "gemini"):
        invalid("type", "type must be openai, openai_compatible, anthropic, or gemini.")
    try:
        url = urlparse(str(entry.get("base_url", "")))
        valid_url = url.scheme in {"https", "http"} and bool(url.netloc)
    except ValueError:
        valid_url = False
    if not valid_url:
        invalid("base_url", "base_url must start with http:// or https:// and include a host.")
    if not isinstance(entry.get("default_model"), str) or not entry["default_model"].strip():
        invalid("default_model", "default_model must be a nonempty model name.")
    keys = entry.get("keys")
    if not isinstance(keys, list) or not keys or not isinstance(keys[0], str) or not keys[0].strip():
        fail(f'No API key found for service "{service}".\n'
             f'  Open {CONFIG.as_posix()} and put your key first in the "keys" list of the "{service}" service.\n'
             "  If you are an artifact evaluator, copy reviewer_config.json from HotCRP over config/api_config.json.")
    key = keys[0].strip()
    if key.startswith("<") or "YOUR_" in key.upper():
        fail(f'The API key for service "{service}" is still a placeholder (for example, "<YOUR_API_KEY_HERE>").\n'
             "  Replace it with a real key in config/api_config.json, or copy reviewer_config.json from HotCRP over that file.")
    print(f'  OK: API configuration loaded for "{service}" (credentials will be tested by the first live call below)')

    output = Path(os.environ["OUTPUT_ROOT"])
    try:
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryFile(dir=output) as probe:
            probe.write(b"permission check")
            probe.flush()
    except OSError:
        fail(f'Cannot create or write to output directory "{output}".\n'
             "  Give your account write permission, or set OUTPUT_ROOT to a writable directory and rerun.")
    print(f"  OK: output directory is writable ({output})")


try:
    check()
except Exception as exc:
    technical_detail(exc)
    fail("Could not finish checking your setup.\n"
         "  Check config/api_config.json; if malformed, re-copy reviewer_config.json from HotCRP.\n"
         f'  Install dependencies using the project interpreter: "{sys.executable}" -m pip install -r requirements.txt\n'
         "  Make sure your account can read the configuration and write to OUTPUT_ROOT (default: output/quickstart).")
print("Setup checks passed.")
PY

export SEED_EXAMPLES="data/diameter/seed_examples.md"
export TARGETS="data/diameter/evaluation_dataset.csv"
export ATTACK_SEEDS=4
export SAFE_SEEDS=14
export ATTACK_SIDE=request
export PROMPT_WORKERS=2
export WORKERS=1
export TARGET_NUMBERS=6
create_run_dir() {
  "${PYTHON}" - "$1" <<'PY'
import sys
from datetime import datetime
from pathlib import Path

parent = Path(sys.argv[1])
stem = "run_" + datetime.now().strftime("%Y%m%d_%H%M%S")
index = 1
while True:
    name = stem if index == 1 else f"{stem}_{index}"
    path = parent / name
    try:
        path.mkdir()
    except FileExistsError:
        index += 1
        continue
    print(path.as_posix())
    break
PY
}

quickstart_root="${OUTPUT_ROOT}"
smoke_cache() {
  "${PYTHON}" - "$1" "${quickstart_root}" "${SERVICE}" "${2:-}" <<'PY'
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

mode, root, service, run = sys.argv[1:]
root = Path(root).resolve()
config = json.loads(Path("config/api_config.json").read_text(encoding="utf-8-sig"))
digest = hashlib.sha256(json.dumps([service, config[service]], sort_keys=True).encode())
paths = sorted(Path("src").glob("*.py")) + [
    Path("scripts/run_lens.sh"), Path("scripts/run_quickstart.sh"),
    Path("requirements.txt"), Path("data/diameter/seed_examples.md"),
    Path("data/diameter/evaluation_dataset.csv"),
]
for path in paths:
    digest.update(str(path).encode())
    digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
marker = root / (".smoke_success_" + digest.hexdigest())

def valid(path):
    if path.parent != root or not path.name.startswith("run_"):
        return False
    return all((path / "lens" / name).is_file() and
               (path / "lens" / name).stat().st_size > 0
               for name in ["val006_response.txt", "instruction_used.txt", "context_prompt_used.txt"])

if mode == "read":
    try:
        cached = (root / marker.read_text(encoding="utf-8").strip()).resolve()
        if valid(cached):
            print(cached.as_posix())
    except (OSError, ValueError):
        pass
elif mode == "save":
    completed = Path(run).resolve()
    if not valid(completed):
        sys.exit("Cannot record smoke success: required report or prompts are missing.")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=root, delete=False) as handle:
        handle.write(completed.name)
        temporary = Path(handle.name)
    try:
        os.replace(temporary, marker)
    finally:
        temporary.unlink(missing_ok=True)
PY
}

cached_run="$(smoke_cache read)"
if [[ -n "${cached_run}" ]]; then
  export OUTPUT_ROOT="${cached_run}"
  echo "[2/2] Previous smoke test passed for this setup; skipping API calls."
else
if ! run_dir="$(create_run_dir "${OUTPUT_ROOT}")"; then
  echo "Cannot create a run directory under ${OUTPUT_ROOT}. Check write permissions and available disk space." >&2
  exit 1
fi
export OUTPUT_ROOT="${run_dir}"

echo "[2/2] Running LENS on benchmark field 6 with seeds 4 and 14..."
echo "Output directory: ${OUTPUT_ROOT}"
if ! bash scripts/run_lens.sh; then
  echo "Quick start did not complete. See the error above." >&2
  echo "For configuration or authentication errors, re-copy reviewer_config.json from HotCRP over config/api_config.json." >&2
  echo "For quota or connection errors, check your provider balance and network access before retrying." >&2
  echo "Partial output: ${OUTPUT_ROOT}" >&2
  exit 1
fi
if [[ ! -s "${OUTPUT_ROOT}/lens/val006_response.txt" ]]; then
  echo "Quick start did not produce the expected report: ${OUTPUT_ROOT}/lens/val006_response.txt" >&2
  echo "Check the preceding model errors and API configuration, then rerun." >&2
  exit 1
fi

smoke_cache save "${OUTPUT_ROOT}"
fi

echo "========================================"
echo "Quick start finished successfully."
echo "  Report: ${OUTPUT_ROOT}/lens/val006_response.txt"
echo "  To repeat the smoke test, delete .smoke_success_* in ${quickstart_root}."
echo "  A saved success does not guarantee current API availability or balance."
echo "========================================"

# Require terminal input and output so redirected runs never prompt for paid work.
if [[ ! -t 0 || ! -t 1 ]]; then
  echo "Smoke test completed. For more experiments, run interactively in a terminal"
  echo "or run: bash scripts/run_lens.sh (additional API charges apply)."
  exit 0
fi

while true; do
  echo
  echo "Select an experiment (current service: ${SERVICE})"
  echo '  [2] LENS on the 40-field benchmark (~89 API calls; ~$7; ~5 min)'
  echo '  [3] LENS effectiveness on 8 different configurations (~449 API calls; ~$29; ~40 min)'
  echo '  [4] Configuration study with only one combination (~950 API calls; ~$62; ~55 min)'
  echo '  [5] Protocol-level analysis on 100 fields (~200 API calls; ~$13, ~15min)'
  echo '  [6] Generalizability on MQTT, 67 fields (~143 API calls; ~$9; ~10 min)'
  echo "  [q] Quit [default; no further charges]"
  if ! read -r -p "Choose [q]: " choice; then
    echo
    exit 0
  fi
  case "${choice}" in
    ""|q|Q) exit 0 ;;
    2)
      experiment=lens
      script=scripts/run_lens.sh
      calls="89"
      estimated_cost="7"
      ;;
    3)
      experiment=lens_effectiveness
      script=scripts/run_lens_effectiveness.sh
      calls="449"
      estimated_cost="29"
      ;;
    4)
      experiment=configuration_study
      script=scripts/run_configuration_study.sh
      calls="950"
      estimated_cost="62"
      ;;
    5)
      experiment=protocol_level_analysis
      script=scripts/run_protocol_level_analysis.sh
      calls="200"
      estimated_cost="13"
      ;;
    6)
      experiment=generalizability
      script=scripts/run_generalizability.sh
      calls="143"
      estimated_cost="9"
      ;;
    *)
      echo "Choose 2, 3, 4, 5, 6, or q. No experiment started."
      continue
      ;;
  esac
  if ! read -r -p "Option [${choice}]: about ${calls} live API calls using ${SERVICE}, reference budget \$${estimated_cost}. Continue? [y/N] " confirmation; then
    echo
    exit 0
  fi
  case "${confirmation}" in
    y|Y) ;;
    *) echo "Cancelled. No experiment started."; continue ;;
  esac

  (
    # Do not inherit the smoke test's target filter, concurrency, or output path.
    export TARGET_NUMBERS=""
    export WORKERS=20
    export PROMPT_WORKERS=2
    export ATTACK_SIDE=request
    unset SEARCH_SERVICE
    case "${choice}" in
      4)
        export SAMPLES_PER_N=1
        export COMBO_WORKERS=1
        ;;
      5)
        export INTERFACE=s6a
        export LIMIT=100
        export PROMPT_DIR="${OUTPUT_ROOT}/lens"
        if [[ ! -s "${PROMPT_DIR}/instruction_used.txt" || ! -s "${PROMPT_DIR}/context_prompt_used.txt" ]]; then
          echo "Smoke-test prompts are missing from ${PROMPT_DIR}. Complete Quick Start again before protocol analysis." >&2
          exit 1
        fi
        ;;
      6)
        export PROTOCOLS=mqtt
        export ROUNDS=3
        ;;
    esac
    parent="output/${experiment}"
    if ! mkdir -p "${parent}"; then
      echo "Cannot create ${parent}. Check directory permissions." >&2
      exit 1
    fi
    if ! experiment_dir="$(create_run_dir "${parent}")"; then
      echo "Cannot create a run directory under ${parent}. Check write permissions and disk space." >&2
      exit 1
    fi
    export OUTPUT_ROOT="${experiment_dir}"
    echo "Starting ${experiment}. Output directory: ${OUTPUT_ROOT}"
    # Propagate failure explicitly: this subshell is used in a conditional.
    bash "${script}" || exit "$?"
    echo "Experiment completed. Output directory: ${OUTPUT_ROOT}"
  ) && experiment_status=0 || experiment_status=$?
  if [[ "${experiment_status}" -ne 0 ]]; then
    echo "Experiment stopped (exit ${experiment_status}). Check the errors above; it will not restart automatically." >&2
  fi
done
