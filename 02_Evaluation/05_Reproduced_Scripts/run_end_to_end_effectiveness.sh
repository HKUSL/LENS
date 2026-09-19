#!/usr/bin/env bash
set -euo pipefail

# Section 4.2 / Tables 5-6: four models, five independent LENS runs each.
# The seed IDs are fixed across runs, but every run has a separate directory
# and re-infers the initial p_exp, p_evi, and refined p_exp from scratch.

cd "$(dirname "${BASH_SOURCE[0]}")/../../01_LENS"

PYTHON="${PYTHON:-python}"
SERVICES="${SERVICES:-gpt5.4 glm claude gemini}"
RUNS="${RUNS:-5}"
WORKERS="${WORKERS:-20}"
PROMPT_WORKERS="${PROMPT_WORKERS:-7}"
OUTPUT_ROOT="${OUTPUT_ROOT:-output/paper/end_to_end_effectiveness}"

for service in ${SERVICES}; do
  for run in $(seq 1 "${RUNS}"); do
    run_root="${OUTPUT_ROOT}/${service}/run${run}"
    prompt_root="${run_root}/prompt_construction"

    experiment_args=(
      -m src.experiment
      --services "${service}"
      --sample-counts 1
      --attack-side request
      --attack-indices 4
      --safe-indices 14
      --safe-mode matched
      --max-support-sets 1
      --info-rounds 0
      --workers "${PROMPT_WORKERS}"
      --seed-examples data/diameter/seed_examples.md
      --output-dir "${prompt_root}"
    )
    "${PYTHON}" "${experiment_args[@]}"

    round0="$(find "${prompt_root}" -type d -name round_00 -print -quit)"
    if [[ -z "${round0}" ]]; then
      echo "No round_00 prompt directory found under ${prompt_root}" >&2
      exit 1
    fi

    method_args=(
      -m src.evaluate_lens_effectiveness
      --service "${service}"
      --configurations lens
      --evaluation-dataset data/diameter/evaluation_dataset.csv
      --seed-examples data/diameter/seed_examples.md
      --seed-attacks 4
      --seed-safes 14
      --induced-prompt-dir "${round0}"
      --seed-failure-dir "${round0}"
      --workers "${WORKERS}"
      --analysis-websearch
      --output-dir "${run_root}"
    )
    "${PYTHON}" "${method_args[@]}"
  done
done
