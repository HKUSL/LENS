"""Hand-written baseline prompt builders for method evaluation.

These are independent of `prompts.py` and DO NOT touch any of the project's
prompt-induction or context-collection templates.

This file owns five hand-written prompts:

  * ``build_zero_shot_prompt`` / ``build_few_shot_prompt`` -- the Simple
    Prompt and Few-shot Examples baselines.
  * ``build_naive_context_prompt`` -- a direct context-collection prompt.
  * ``build_spec_context_prompt`` -- a neutral 3GPP-spec context prompt used
    by Field-Relevant Retrieval.
  * ``build_poc_context_prompt`` -- a PoC-oriented context prompt used for
    Exploitability-Relevant Retrieval.
"""
from __future__ import annotations

from typing import List

from .samples import Sample, build_input_for_case


SHARED_TASK_DESCRIPTION = (
    "You are an expert in the Diameter protocol. Analyze whether a specific Diameter field can be exploit and generate corresponding exploitability analysis report. If it is exploitable, please generate PoC. "
)


def build_zero_shot_prompt(target_input: str) -> str:
    return (
        f"Task:\n{SHARED_TASK_DESCRIPTION}\n\n"
        f"Target field:\n{target_input.strip()}\n"
    )


def build_few_shot_prompt(target_input: str, seeds: List[Sample]) -> str:
    parts = [
        "=== Prompt ===",
        SHARED_TASK_DESCRIPTION,
        "",
        "=== Demonstrations ===",
    ]
    for i, seed in enumerate(seeds, 1):
        demo_input = build_input_for_case(seed)
        parts.extend(
            [
                f"--- Demonstration {i} ({seed.label}) ---",
                "Target Field:",
                demo_input.strip(),
                "Expected Report:",
                seed.content.strip(),
                "",
            ]
        )
    parts.extend(
        [
            "=== Target DiameterField ===",
            target_input.strip(),
            "",
        ]
    )
    return "\n".join(parts)


NAIVE_CONTEXT_INSTRUCTION = (
    "You are an expert in the Diameter protocol. "
    "I need to analyze the exploitability of the Diameter field below. "
    "Please search all the relevant 3GPP specifications and collect all protocol evidence related to this field."
)

SPEC_CONTEXT_INSTRUCTION = (
    "You are an expert in 3GPP Diameter specifications. "
    "Given the target Diameter field below, search all the relevant 3GPP specifications and collect all protocol evidence related to this field."
)

POC_CONTEXT_INSTRUCTION = (
    "You are an expert in 3GPP Diameter specifications and Diameter packet construction. "
    "We will later perform exploitability analysis for the target field and, if it is exploitable, generate a corresponding forged Diameter Request PoC packet. "
    "Search all relevant 3GPP specifications and collect the protocol information needed for those later steps."
)

def build_naive_context_prompt(target_input: str) -> str:
    """Build a direct context-collection prompt.

    Self-contained: includes the target field directly, so the caller can
    send the returned string to the LLM without any further wrapping.
    """
    return (
        f"{NAIVE_CONTEXT_INSTRUCTION}\n\n"
        f"=== Target Diameter field ===\n"
        f"{target_input.strip()}\n\n"
        "Output only the protocol evidence.\n"
    )


def build_spec_context_prompt(target_input: str) -> str:
    """Build a neutral 3GPP-spec context prompt.

    This is self-contained like ``build_naive_context_prompt`` but deliberately
    asks for specification context instead of exploitability-oriented context.
    """
    return (
        f"{SPEC_CONTEXT_INSTRUCTION}\n\n"
        f"=== Target Diameter field ===\n"
        f"{target_input.strip()}\n\n"
        "Output only neutral protocol evidence.\n"
    )


def build_poc_context_prompt(target_input: str) -> str:
    """Build a PoC-oriented 3GPP context prompt.

    This remains a context-collection prompt and does not perform the final
    classification or generate the PoC itself.
    """
    return (
        f"{POC_CONTEXT_INSTRUCTION}\n\n"
        f"=== Target Diameter field ===\n"
        f"{target_input.strip()}\n\n"
        "Output only the protocol evidence needed for those later steps.\n"
    )


def build_cot_few_shot_prompt(target_input: str, seeds: List[Sample]) -> str:
    base = build_few_shot_prompt(target_input, seeds)
    return base + "\nThink step by step, then end with the Classification line.\n"
