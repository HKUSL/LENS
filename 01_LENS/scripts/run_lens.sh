#!/usr/bin/env bash
set -euo pipefail

# Run LENS on a user-provided protocol target set.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python}"
SERVICE="${SERVICE:-gpt5.4}"
SEED_EXAMPLES="${SEED_EXAMPLES:-data/diameter/seed_examples.md}"
TARGETS="${TARGETS:-data/diameter/evaluation_dataset.csv}"
ATTACK_SEEDS="${ATTACK_SEEDS:-4}"
SAFE_SEEDS="${SAFE_SEEDS:-14}"
ATTACK_SIDE="${ATTACK_SIDE:-all}"
PROMPT_WORKERS="${PROMPT_WORKERS:-2}"
WORKERS="${WORKERS:-4}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/lens}"
PROMPT_ROOT="${OUTPUT_ROOT}/prompt_construction"

if [[ ! -f "${SEED_EXAMPLES}" ]]; then
  echo "Seed file not found: ${SEED_EXAMPLES}" >&2
  exit 2
fi
if [[ ! -f "${TARGETS}" ]]; then
  echo "Target file not found: ${TARGETS}" >&2
  exit 2
fi
if [[ -z "${ATTACK_SEEDS}" || -z "${SAFE_SEEDS}" ]]; then
  echo "ATTACK_SEEDS and SAFE_SEEDS must not be empty." >&2
  exit 2
fi

IFS=',' read -r -a attack_seed_ids <<< "${ATTACK_SEEDS}"
IFS=',' read -r -a safe_seed_ids <<< "${SAFE_SEEDS}"
if [[ "${#attack_seed_ids[@]}" -ne "${#safe_seed_ids[@]}" ]]; then
  echo "ATTACK_SEEDS and SAFE_SEEDS must contain the same number of IDs." >&2
  exit 2
fi
sample_count="${#attack_seed_ids[@]}"

experiment_args=(
  -m src.experiment
  --services "${SERVICE}"
  --sample-counts "${sample_count}"
  --attack-side "${ATTACK_SIDE}"
  --attack-indices "${ATTACK_SEEDS}"
  --safe-indices "${SAFE_SEEDS}"
  --safe-mode matched
  --max-support-sets 1
  --info-rounds 0
  --workers "${PROMPT_WORKERS}"
  --seed-examples "${SEED_EXAMPLES}"
  --output-dir "${PROMPT_ROOT}"
)
"${PYTHON}" "${experiment_args[@]}"

round0="$(find "${PROMPT_ROOT}/${SERVICE}" -type d -name round_00 -print -quit)"
if [[ -z "${round0}" ]]; then
  echo "No round_00 prompt directory found under ${PROMPT_ROOT}/${SERVICE}." >&2
  exit 1
fi

lens_args=(
  -m src.evaluate_lens_effectiveness
  --service "${SERVICE}"
  --configurations lens
  --evaluation-dataset "${TARGETS}"
  --seed-examples "${SEED_EXAMPLES}"
  --seed-attacks "${ATTACK_SEEDS}"
  --seed-safes "${SAFE_SEEDS}"
  --induced-prompt-dir "${round0}"
  --seed-failure-dir "${round0}"
  --workers "${WORKERS}"
  --analysis-websearch
  --output-dir "${OUTPUT_ROOT}"
)
if [[ -n "${TARGET_NUMBERS:-}" ]]; then
  lens_args+=(--include-numbers "${TARGET_NUMBERS}")
fi
if [[ -n "${SEARCH_SERVICE:-}" ]]; then
  lens_args+=(--search-service "${SEARCH_SERVICE}")
fi
"${PYTHON}" "${lens_args[@]}"
