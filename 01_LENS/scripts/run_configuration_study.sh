#!/usr/bin/env bash
set -euo pipefail

# Section 4.4 Configuration Study:
#   Figure 4: 1..7 example pairs, ten random combinations per setting.
#   Table 9: information used for p_evi inference.

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PYTHON="${PYTHON:-python}"
SERVICE="${SERVICE:-gpt5.4}"
WORKERS="${WORKERS:-10}"
COMBO_WORKERS="${COMBO_WORKERS:-2}"
PROMPT_WORKERS="${PROMPT_WORKERS:-7}"
RNG_SEED="${RNG_SEED:-42}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/paper/configuration_study}"

number_args=(
  -m src.evaluate_number_of_examples
  --service "${SERVICE}"
  --evaluation-dataset data/diameter/evaluation_dataset.csv
  --seed-examples data/diameter/seed_examples.md
  --ns 1,2,3,4,5,6,7
  --samples-per-n 10
  --rng-seed "${RNG_SEED}"
  --workers "${WORKERS}"
  --combo-workers "${COMBO_WORKERS}"
  --output-dir "${OUTPUT_ROOT}/number_of_examples"
)
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
if [[ -n "${SEARCH_SERVICE:-}" ]]; then
  information_args+=(--search-service "${SEARCH_SERVICE}")
fi
"${PYTHON}" "${information_args[@]}"
