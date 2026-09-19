#!/usr/bin/env bash
set -euo pipefail

# Section 5.1 protocol-level analysis over all 600 S6a + 166 Cx fields.
# Use the LENS prompt directory from the selected first GPT Table 5 run:
#   PROMPT_DIR=output/paper/end_to_end_effectiveness/gpt5.4/run1/lens \
#     bash scripts/run_protocol_level_analysis.sh

cd "$(dirname "${BASH_SOURCE[0]}")/../../01_LENS"

PYTHON="${PYTHON:-python}"
SERVICE="${SERVICE:-gpt5.4}"
WORKERS="${WORKERS:-20}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/paper/protocol_level_findings}"

if [[ -z "${PROMPT_DIR:-}" ]]; then
  echo "PROMPT_DIR must point to a completed LENS configuration directory." >&2
  exit 2
fi

args=(
  -m src.evaluate_protocol_level_findings
  --service "${SERVICE}"
  --s6a-file data/diameter/s6a_field_paths.txt
  --cx-file data/diameter/cx_field_paths.txt
  --message-side all
  --prompt-dir "${PROMPT_DIR}"
  --workers "${WORKERS}"
  --output-dir "${OUTPUT_ROOT}"
)
"${PYTHON}" "${args[@]}"
