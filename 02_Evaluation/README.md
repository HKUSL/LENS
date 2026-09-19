# LENS Evaluation

This directory contains the prompts, evaluation materials, implementation-confirmed PoCs, and scripts used to reproduce the experiments reported in the paper.

The LENS implementation itself is under [`../01_LENS/`](../01_LENS/).

## Directory Guide

- [`01_Prompts/`](01_Prompts/) contains the inferred and refined exploitability-analysis prompt (`p_exp`) and evidence-collection prompt (`p_evi`), together with the meta-prompts used to construct them.
- [`02_Evaluation_Material/`](02_Evaluation_Material/) contains the 40-field Diameter evaluation benchmark, expert-written reference analyses and PoCs, and the materials used for the effectiveness experiments.
- [`03_Prompt_Inference_Dataset/`](03_Prompt_Infered%20Dataset/) contains the separate 16-case prompt-inference dataset used in Section 4.4 to study the number of examples required for prompt inference. It includes eight exploitable and eight non-exploitable cases.
- [`04_Confirmed_PoCs/`](04_Confirmed_PoCs/) contains the 64 LENS-generated Diameter PoCs whose predicted security impacts were confirmed during the implementation-level assessment.
- [`05_Reproduced_Scripts/`](05_Reproduced_Scripts/) contains the scripts for reproducing the experiments reported in the paper. The scripts run the implementation under `../01_LENS/`.

## Before Reproduction

Install and configure LENS by following [`../01_LENS/README.md`](../01_LENS/README.md). The experiments require Python 3.9 or later, Bash, Internet access, and valid credentials for the selected model and search services. WSL is recommended on Windows.

Run the commands below from the artifact repository root. Full runs make paid API and web-search calls. Use a fresh `OUTPUT_ROOT` for each independent run; default outputs are written under `01_LENS/output/paper/`.

## Reproducing the Paper Experiments

### Section 4.2 and Tables 5–6: End-to-End Effectiveness

Evaluate four underlying models over five independent LENS runs. Each run re-infers and refines the prompts before analyzing all 40 fields.

```bash
bash 02_Evaluation/05_Reproduced_Scripts/run_end_to_end_effectiveness.sh
```

### Section 4.3 and Tables 7–8: Understanding LENS Effectiveness

Evaluate the contributions of exploitability-analysis discipline, protocol evidence, guidance inference, and joint prompt refinement.

```bash
bash 02_Evaluation/05_Reproduced_Scripts/run_lens_effectiveness.sh
```

### Section 4.4, Figure 4, and Table 9: Configuration Study

Study the number of examples required for prompt inference and the information supplied when inferring `p_evi`.

```bash
bash 02_Evaluation/05_Reproduced_Scripts/run_configuration_study.sh
```

### Section 5.1: Protocol-Level Diameter Analysis

Analyze the complete S6a and Cx field-path sets. This experiment uses the prompts produced by the first GPT-5.4 run from Section 4.2, so complete the end-to-end experiment first.

```bash
PROMPT_DIR=output/paper/end_to_end_effectiveness/gpt5.4/run1/lens \
  bash 02_Evaluation/05_Reproduced_Scripts/run_protocol_level_analysis.sh
```

### Section 6 and Table 18: Generalizability

Apply the LENS methodology to 16 additional protocols.

```bash
bash 02_Evaluation/05_Reproduced_Scripts/run_generalizability.sh
```

The protocol-level manual audit and PoC consequence categorization reported in the paper are not automated by these scripts. Because LENS relies on externally hosted LLMs and web search, exact outputs may vary across model versions and independent runs.


## Data Collection Ethics
We constructed the 40-field ground-truth dataset from fields supported by our testing environment, enabling experimental validation. Two authors with experience in cellular protocol analysis independently assessed each field through analysis of 3GPP specifications and experimental validation. They then compared their assessments, resolved disagreements by revisiting specifications and experimental results until reaching consensus, and jointly finalized the labels, analysis reports, and PoCs (for exploitable fields). We did not retain the pre-consensus annotations and thus cannot reliably report inter-annotator agreement retrospectively. Throughout the entire process, including PoC construction, neither author saw any LENS outputs.