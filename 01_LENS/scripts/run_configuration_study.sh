#!/usr/bin/env bash
set -euo pipefail

# Section 4.4 Configuration Study:
#   Figure 4: 1..7 example pairs, one random combination per setting by default.
#   Table 9: information used for p_evi inference.

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
WORKERS="${WORKERS:-10}"
COMBO_WORKERS="${COMBO_WORKERS:-2}"
PROMPT_WORKERS="${PROMPT_WORKERS:-7}"
RNG_SEED="${RNG_SEED:-42}"
SAMPLES_PER_N="${SAMPLES_PER_N:-1}"
# Empty selects the full benchmark; set comma-separated IDs to run a subset.
TARGET_NUMBERS="${TARGET_NUMBERS-}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/configuration_study}"

number_args=(
  -m src.evaluate_number_of_examples
  --service "${SERVICE}"
  --evaluation-dataset data/diameter/evaluation_dataset.csv
  --seed-examples data/diameter/seed_examples.md
  --ns 1,2,3,4,5,6,7
  --samples-per-n "${SAMPLES_PER_N}"
  --rng-seed "${RNG_SEED}"
  --workers "${WORKERS}"
  --combo-workers "${COMBO_WORKERS}"
  --output-dir "${OUTPUT_ROOT}/number_of_examples"
)
if [[ -n "${TARGET_NUMBERS}" ]]; then
  number_args+=(--include-numbers "${TARGET_NUMBERS}")
fi
"${PYTHON}" "${number_args[@]}"

experiment_args=(
  -m src.experiment
  --services "${SERVICE}"
  --sample-counts 1
  --attack-side request
  --attack-indices 4
  --safe-indices 14
  --safe-mode matched
  --max-support-sets 1
  --info-rounds 0
  --workers "${PROMPT_WORKERS}"
  --seed-examples data/diameter/seed_examples.md
  --output-dir "${OUTPUT_ROOT}/information_for_pevi/prompt_construction"
)
"${PYTHON}" "${experiment_args[@]}"

round0="$(find "${OUTPUT_ROOT}/information_for_pevi/prompt_construction" -type d -name round_00 -print -quit)"
if [[ -z "${round0}" ]]; then
  echo "No round_00 prompt directory found for Table 9." >&2
  exit 1
fi

information_args=(
  -m src.evaluate_lens_effectiveness
  --service "${SERVICE}"
  --configurations llm_generated_writeup_only,add_expert_written_writeup,add_analysis_history
  --evaluation-dataset data/diameter/evaluation_dataset.csv
  --seed-examples data/diameter/seed_examples.md
  --seed-attacks 4
  --seed-safes 14
  --induced-prompt-dir "${round0}"
  --seed-failure-dir "${round0}"
  --workers "${WORKERS}"
  --no-analysis-websearch
  --output-dir "${OUTPUT_ROOT}/information_for_pevi/configurations"
)
if [[ -n "${TARGET_NUMBERS}" ]]; then
  information_args+=(--include-numbers "${TARGET_NUMBERS}")
fi
if [[ -n "${SEARCH_SERVICE:-}" ]]; then
  information_args+=(--search-service "${SEARCH_SERVICE}")
fi
"${PYTHON}" "${information_args[@]}"
