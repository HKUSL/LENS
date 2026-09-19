# LENS

LENS is an LLM-based system for reliable field-level Diameter exploitability analysis. It infers exploitability-analysis discipline from expert-written exploit writeups and evidence-collection guidance from exploitability-analysis failures.

Given a target Diameter field, LENS collects the protocol evidence needed for exploitability analysis, assesses the field's exploitability, and generates an exploitability-analysis report and a corresponding PoC when applicable.

This directory contains the LENS analysis and evaluation pipeline, together with the datasets and scripts used for the experiments reported in *When Core-Network Elements Become Reachable: Field-Level Exploitability Analysis in Diameter*.

## Repository Layout

- `src/`: LENS implementation
- `data/`: seed examples, evaluation datasets, and protocol target sets
- `scripts/`: entry points for running LENS and reproducing the paper experiments
- `config/`: API configuration

Generated results are written to `output/` by default.

## Requirements

- Python 3.9+
- Bash
- API credentials for at least one supported model
- Internet access for model API calls and web search

The experiment scripts require Bash. On Windows, WSL is recommended.

## Installation

From the repository root, create a Python virtual environment and install the required packages:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```



## Model and API Configuration

Set the API credentials and model names in `config/api_config.json`. The provided configuration matches the models used in the paper, but the model settings can be changed if needed.

## Quick Start

To make sure the setup works, the following command runs LENS with GPT-5.4 on one field from the 40-field Diameter benchmark:

```bash
bash scripts/run_quickstart.sh
```

This run makes paid API and web-search calls. Its output is saved under `output/quickstart/evaluation/lens/`.

## Running LENS on a New Protocol

LENS can be applied to a new protocol by providing two main inputs: a set of expert-reviewed seed examples and a set of target fields to analyze. The example below uses Diameter, but the same workflow applies to other protocols with protocol-specific field representations.

### 1. Prepare Seed Examples

Prepare expert-reviewed exploitable and non-exploitable examples following the format of `data/diameter/seed_examples.md`.

Each example should identify the target field, describe the threat model, provide an expert exploitability analysis, and include an `ATTACK` or `SAFE` classification. ATTACK examples should also include the corresponding attack procedure and PoC. At least one example from each class is required.

Examples for the non-Diameter protocols evaluated in the paper are available under `data/non_diameter/seed/`. For a new protocol, include a `**Protocol:**` field in each seed example so that LENS can identify the protocol.

### 2. Prepare the Target Fields

Prepare the set of protocol fields to be analyzed by LENS. The exact representation depends on the protocol.

For example, Diameter targets can be represented as:

```csv
number,iface,message,avp_path
1,s6a,Update-Location-Request,ULR-Flags
2,cx,User-Authorization-Request,User-Authorization-Type
```

For another protocol, use a target representation that captures its message and field structure. The loader accepts CSV, JSON, and message-to-field text files. Examples for the additional protocols evaluated in the paper are available under `data/non_diameter/target/`.

A ground-truth `label` is only needed when evaluating LENS on an already labeled dataset.

### 3. Run LENS

For the Diameter example above:

```bash
SEED_EXAMPLES=data/diameter/my_seed_examples.md \
  TARGETS=data/diameter/my_targets.csv \
  ATTACK_SEEDS=1 \
  SAFE_SEEDS=2 \
  OUTPUT_ROOT=output/my_analysis \
  bash scripts/run_lens.sh
```

The selected seed IDs refer to the numbered examples in the seed file. To use multiple seed pairs, provide comma-separated ATTACK and SAFE IDs with the same number of entries. The default model is `gpt5.4`. Set `SERVICE` to another configured model if needed.

LENS infers and refines its prompts, collects protocol evidence for each target, and generates the corresponding exploitability-analysis reports and PoCs when applicable. Results are written under `output/my_analysis/lens/`. Review the generated reports before using the findings; LENS does not execute PoCs or confirm implementation-level impact.

## Datasets

The Diameter seed examples, 40-field evaluation benchmark, and full S6a/Cx target sets are under `data/diameter/`. The datasets for the 16 additional protocols are under `data/non_diameter/`.

## Outputs

Experiment outputs are written under `output/`. The main files include:

- `*_response.txt`: generated evidence or exploitability-analysis reports
- `evaluation_summary.json` / `.csv`: automatically computed evaluation results
- `manual_rubric.csv`: manual-review template for generated analyses and PoCs

The automatically computed metrics use the parsed `ATTACK`/`SAFE` classification. Reproducing the final metrics reported in the paper additionally requires completing the semantic and PoC review in `manual_rubric.csv`.