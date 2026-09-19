# LENS

This artifact accompanies the IEEE S&P 2027 submission *When Core-Network Elements Become Reachable: Field-Level Exploitability Analysis in Diameter*.

LENS is an LLM-based system for reliable field-level Diameter exploitability analysis. It infers exploitability-analysis discipline from expert-written exploit writeups and evidence-collection guidance from exploitability-analysis failures. Given a target field, LENS collects the protocol evidence needed for analysis, assesses its exploitability, and generates a corresponding PoC when applicable.

The paper manuscript is available as [`LENS.pdf`](LENS.pdf).

![LENS paper preview](https://evidrawbed.oss-cn-beijing.aliyuncs.com/20260919161558648.png)

## Artifact Contents

- [`01_LENS/`](01_LENS/) contains the runnable LENS implementation and datasets. See its [README](01_LENS/README.md) for installation, configuration, and usage.
- [`02_Evaluation/`](02_Evaluation/) contains the prompts, evaluation materials, implementation-confirmed PoCs, and scripts for reproducing the paper experiments. See its [README](02_Evaluation/README.md) for details.
- [`03_Demo_Video/`](03_Demo_Video/) contains six demonstration videos from the implementation-level assessment, which can also be viewed on the [HKUSL website](https://hkusl.github.io/LENS/).

## Quick Start

LENS requires Python 3.9+, Bash, Internet access, and API credentials for a supported model.

```bash
cd 01_LENS
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
bash scripts/run_quickstart.sh
```

The quick-start example runs LENS on one field from the Diameter evaluation benchmark. For model configuration, custom inputs, and applying LENS to another protocol, see [`01_LENS/README.md`](01_LENS/README.md).

## Reproducing the Paper Experiments

The scripts for reproducing the experiments in Sections 4.2--6 are documented in [`02_Evaluation/README.md`](02_Evaluation/README.md).

Some reported results additionally require manual semantic and PoC review. The corresponding evaluation materials are also provided under [`02_Evaluation/`](02_Evaluation/).

Because LENS relies on externally hosted LLMs and web search, exact outputs may vary across model versions and independent runs.

## Demonstration Videos

Please see [`03_Demo_Video/README.md`](03_Demo_Video/README.md) for six representative demonstration videos covering five security-consequence categories and one representative attack.

## Responsible Use

This artifact contains security-analysis prompts and protocol-level PoCs. Use them only on systems and networks that you own or are explicitly authorized to test. PoC execution should be performed only in isolated testing environments.
