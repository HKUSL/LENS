#!/usr/bin/env bash
set -euo pipefail

# Run the paper LENS configuration on one Diameter benchmark field.

cd "$(dirname "${BASH_SOURCE[0]}")/../../01_LENS"

export SERVICE="${SERVICE:-gpt5.4}"
export SEED_EXAMPLES="${SEED_EXAMPLES:-data/diameter/seed_examples.md}"
export TARGETS="${TARGETS:-data/diameter/evaluation_dataset.csv}"
export ATTACK_SEEDS="${ATTACK_SEEDS:-4}"
export SAFE_SEEDS="${SAFE_SEEDS:-14}"
export ATTACK_SIDE="${ATTACK_SIDE:-request}"
export PROMPT_WORKERS="${PROMPT_WORKERS:-2}"
export WORKERS="${WORKERS:-1}"
export TARGET_NUMBERS="${TARGET_NUMBERS:-1}"
export OUTPUT_ROOT="${OUTPUT_ROOT:-output/quickstart/evaluation}"

bash scripts/run_lens.sh
