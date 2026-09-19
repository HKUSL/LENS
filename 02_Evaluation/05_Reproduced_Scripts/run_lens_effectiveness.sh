#!/usr/bin/env bash
set -euo pipefail

# Section 4.3 / Tables 7-8 configurations:
#   Simple Prompt, Few-shot Examples, Initial p_exp, Keyword Retrieval,
#   Field-Relevant Retrieval, Exploitability-Relevant Retrieval,
#   Initial p_exp + Initial p_evi, and Refined p_exp + Refined p_evi.

cd "$(dirname "${BASH_SOURCE[0]}")/../../01_LENS"

PYTHON="${PYTHON:-python}"
SERVICE="${SERVICE:-gpt5.4}"
WORKERS="${WORKERS:-20}"
PROMPT_WORKERS="${PROMPT_WORKERS:-7}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/paper/lens_effectiveness}"

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
  --output-dir "${OUTPUT_ROOT}/prompt_construction"
)
"${PYTHON}" "${experiment_args[@]}"

round0="$(find "${OUTPUT_ROOT}/prompt_construction" -type d -name round_00 -print -quit)"
if [[ -z "${round0}" ]]; then
  echo "No round_00 prompt directory found." >&2
  exit 1
fi

method_args=(
  -m src.evaluate_lens_effectiveness
  --service "${SERVICE}"
  --configurations simple_prompt,few_shot_examples,initial_pexp,keyword_retrieval,field_relevant_retrieval,exploitability_relevant_retrieval,initial_pexp_initial_pevi,refined_pexp_refined_pevi
  --evaluation-dataset data/diameter/evaluation_dataset.csv
  --seed-examples data/diameter/seed_examples.md
  --seed-attacks 4
  --seed-safes 14
  --induced-prompt-dir "${round0}"
  --seed-failure-dir "${round0}"
  --workers "${WORKERS}"
  --no-analysis-websearch
  --output-dir "${OUTPUT_ROOT}/configurations"
)
if [[ -n "${SEARCH_SERVICE:-}" ]]; then
  method_args+=(--search-service "${SEARCH_SERVICE}")
fi
"${PYTHON}" "${method_args[@]}"
