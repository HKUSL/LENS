from __future__ import annotations

from typing import Dict, List

from .samples import Sample, build_input_for_case


def _display_label(label: str) -> str:
    normalized = (label or "").strip().upper()
    if normalized == "ATTACK":
        return "Exploitable"
    if normalized == "SAFE":
        return "Non-Exploitable"
    return label


POC_PROMPT_META = (
    "You are given several input-output examples for Diameter field analysis.\n"
    "Each input describes a target Diameter field together with its protocol evidence. "
    "Each output is an expert-written writeup, including a exploitability analysis report and a poc (if the field is exploitable).\n\n"
    "Your task is to infer p_exp, a prompt that captures the "
    "exploitability-analysis discipline reflected by these examples and can "
    "guide analysis of unseen Diameter fields. Output only the inferred prompt."
)


def build_poc_prompt_construction_prompt(
    samples: List[Sample],
    input_override_dir: str = None,
    custom_meta_prompt: str = None,
    record_mode: str = "full",
) -> str:
    parts = [custom_meta_prompt or POC_PROMPT_META, ""]
    compact = record_mode == "minimal"
    for i, sample in enumerate(samples, 1):
        display_label = _display_label(sample.label)
        sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
        sample_output = sample.content
        if compact:
            sample_input = _clip_text(sample_input, 5000, "sample input")
            sample_output = _clip_text(sample_output, 4000, "sample output")
        parts.extend(
            [
                f"Input {i} ({display_label}):",
                sample_input,
                f"Output {i} ({display_label}):",
                sample_output,
                "",
            ]
        )
    parts.append("Output only the instruction.")
    return "\n".join(parts)


def build_exploit_assessment_prompt(sample_input: str, instruction: str) -> str:
    return f"{sample_input.rstrip()}\n\n=== Instruction ===\n\n{instruction.strip()}"


def build_replay_validation_prompt(sample: Sample, generated_report: str) -> str:
    target = f"{sample.message_full}: {sample.target_path}"
    if sample.label == "ATTACK":
        criteria = """The reference report is an ATTACK/PoC report. Mark ACCEPTABLE only if the generated report would let a tester reproduce the same class of attack effect under the stated one-request threat model. It does not need to be textually identical to the reference and may use different non-essential values, identifiers, ordering, or wording.

Focus especially on:
1. Threat model and attacker capability.
2. Attack principle and why the target field matters.
3. Attack procedure and expected effect.
4. Attack message structure.
5. Required AVP/field combinations and concrete values only when they are part of the target-field attack mechanism or explicitly listed in the seed-specific structural checks below.
6. Encoding or value-format requirements when they affect the target-field attack mechanism.
7. Correct message direction and node roles.

Do not invent additional hard structural requirements beyond the seed-specific checks. In particular, do not mark NEEDS_REFINEMENT only because a generic Diameter boilerplate AVP is missing, such as Vendor-Specific-Application-Id, unless that AVP is explicitly listed in the seed-specific checks or the generated report itself makes it central to the target-field attack mechanism.

Mark NEEDS_REFINEMENT when the generated report is SAFE, uses the wrong Diameter message direction or attacker/victim roles, targets the wrong field, depends on a different attack mechanism, contradicts a seed-specific structural check, omits required target-mechanism AVPs or values, or gives message-construction details that would likely prevent reproducing the same target-field security effect."""
    else:
        criteria = """The reference report is a SAFE/non-exploitable report. Mark ACCEPTABLE only if the generated report also concludes SAFE/non-exploitable for a compatible reason under the stated one-request threat model and does not provide a practical attack. Exact wording is not required. Mark NEEDS_REFINEMENT if the generated report claims ATTACK, invents a practical PoC, treats message-level sensitivity as target-field exploitability, or misses the main safety rationale."""

    structural_checks = _seed_replay_structural_checks(sample)
    if structural_checks:
        criteria = f"""{criteria}

Seed-specific structural checks:
{structural_checks}

For these seed-specific checks, mark NEEDS_REFINEMENT if any required AVP, value, bit setting, or constraint is missing or contradicted, even when the overall classification is ATTACK. Do not add new mandatory AVP requirements that are not listed here."""

    return f"""Compare two reports for the same target field.

Target: {target}
Expected label: {_display_label(sample.label)}

{criteria}

=== Generated Report ===
{generated_report}

=== Reference Report ===
{sample.content}

Output format:
Reasoning: <brief reason>
Conclusion: [ACCEPTABLE/NEEDS_REFINEMENT]"""


def _seed_replay_structural_checks(sample: Sample) -> str:
    checks = {
        1: [
            "The PoC must include PUR-Flags. If PUR-Flags is missing, mark NEEDS_REFINEMENT.",
        ],
        2: [
            "The PoC must include the mandatory AVPs RAT-Type and Visited-PLMN-Id.",
            "ULR-Flags must set bit 5, Initial-Attach-Indicator; the value must be at least 32.",
        ],
        4: [
            "The attack direction must be HSS to MME: the attacker impersonates the HSS and sends an Insert-Subscriber-Data-Request to the victim MME.",
            "The Attack Message must include PDN-Type.",
            "The IDR APN-Configuration PoC must include EPS-Subscribed-QoS-Profile.",
            "The IDR APN-Configuration PoC must include AMBR.",
            "The Attack Message must not include IDR-Flags.",
        ],
        5: [
            "The IDR barring PoC must include Subscriber-Status.",
        ],
        6: [
            "The CLR PoC must include CLR-Flags.",
        ],
        7: [
            "DSR-Flags must set bit 1 for Complete APN Configuration Profile Withdrawal; the expected value is 2.",
            "Context-Identifier must be present and must not be 1.",
        ],
    }
    items = checks.get(sample.number)
    if not items:
        return ""
    return "\n".join(f"- {item}" for item in items)


def build_context_prompt_construction_prompt(
    failed_records: List[Dict],
    support_samples: List[Sample],
    instruction: str,
    info_round: int,
    input_override_dir: str = None,
    record_mode: str = "full",
) -> str:
    protocol_desc = _protocol_description(support_samples)
    field_label = _field_label(support_samples)
    comparison_scope = _comparison_scope(failed_records)
    if info_round > 1:
        failure_desc = (
            f"Below are cases that still fail after {info_round - 1} round(s) of "
            "input enrichment. The enriched inputs shown below were used in both "
            "the prompt induction step and the subsequent PoC-generation step."
        )
        task_item_2 = (
            "Generate a general evidence-collection prompt that takes the current "
            f"enriched {field_label} Information as input and asks for the additional "
            "protocol context needed before PoC generation, grounding that context "
            "in protocol documents or other retrieved evidence."
        )
    else:
        failure_desc = (
            "Below are failed cases from this pipeline. The LLM-generated reports "
            "were tested in a real environment, but the tests did not succeed."
        )
        task_item_2 = (
            "Generate a general evidence-collection prompt that takes the original "
            f"{field_label} Information as input and asks for the additional protocol "
            "context needed before PoC generation, grounding that context in protocol "
            "documents or other retrieved evidence."
        )

    parts = [
        f"I am building an automated pipeline to generate security PoCs for {protocol_desc}.",
        "",
        "The pipeline has three stages:",
        "",
        "Stage 1:",
        "Given target-field inputs and their ground-truth PoC reports, we ask an LLM to induce a PoC-generation prompt that maps each input to its corresponding report.",
        "Stage 2:",
        "We apply the induced PoC-generation prompt back to the same target-field inputs to generate PoC reports.",
        "Stage 3:",
        "A tester follows the generated report, constructs the test message, executes it in a real 4G/LTE environment, and checks whether the expected effect occurs.",
        "",
        failure_desc,
        "",
        "Your goal is to generate a general evidence-collection prompt. This prompt will be used before future PoC generation to collect the protocol context needed for a target field.",
        "",
        "The record below shows the input-output examples used to induce the PoC-generation prompt, followed by the reports generated by that prompt on the same examples. Use this record to reason about what additional protocol facts would have helped the prompt produce the expert-written exploitability-analysis writeup instead of the Failed LLM-Generated Writeups.",
        "",
        "=== Current PoC-Generation Prompt ===",
        _clip_text(instruction, 10000, "current PoC-generation prompt")
        if record_mode == "minimal"
        else instruction,
        "",
    ]

    for idx, record in enumerate(failed_records, 1):
        sample = record["sample"]
        display_label = _display_label(sample.label)
        generated = record.get("generated_report", "")
        sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
        reference = sample.content
        if record_mode == "minimal":
            sample_input = _clip_text(sample_input, 20000, "target field input")
            reference = _clip_text(reference, 20000, "ground-truth report")
            generated = _clip_text(generated, 20000, "generated report")

        parts.extend(
            [
                f"=== Input-Output Pair {idx}: Target Field Input ({display_label}) ===",
                sample_input,
                "",
                f"=== Input-Output Pair {idx}: Ground-truth Expert-Written Report Output ({display_label}) ===",
                reference,
                "",
                f"=== Generated Report for Pair {idx} ===",
                generated,
                "",
            ]
        )

    parts.extend(
        [
            "Your task is:",
            f"1. Compare the expert-written exploitability-analysis writeup with the reports generated by the PoC-generation prompt for {comparison_scope}.",
            "2. Identify what protocol context the generated reports are missing for exploit analysis and message construction.",
            f"3. {task_item_2}",
            "",
            "The prompt you write is a evidence-collection prompt. It is not a PoC report and not a PoC-generation prompt.",
            "",
            "Output only the inferred prompt.",
        ]
    )
    return "\n".join(parts)


def _append_failure_pairs(
    parts: List[str],
    failed_records: List[Dict],
    input_override_dir: str = None,
    record_mode: str = "full",
    include_ground_truth: bool = True,
    include_generated: bool = True,
) -> None:
    for idx, record in enumerate(failed_records, 1):
        sample = record["sample"]
        display_label = _display_label(sample.label)
        sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
        reference = sample.content
        generated = record.get("generated_report", "")
        if record_mode == "minimal":
            sample_input = _clip_text(sample_input, 20000, "target field input")
            reference = _clip_text(reference, 20000, "ground-truth report")
            generated = _clip_text(generated, 20000, "generated report")
        parts.extend(
            [
                f"=== Example {idx}: Diameter field ({display_label}) ===",
                sample_input,
                "",
            ]
        )
        if include_generated:
            parts.extend(
                [
                    f"=== Example {idx}: Failed LLM-Generated Report===",
                    generated,
                    "",
                ]
            )
        if include_ground_truth:
            parts.extend(
                [
                    f"=== Example {idx}: Ground-truth Expert-Written Report ===",
                    reference,
                    "",
                ]
            )


def build_context_prompt_induction_minimal(
    failed_records: List[Dict],
    input_override_dir: str = None,
    record_mode: str = "full",
) -> str:
    """Infer p_evi from LLM-generated and expert-written seed reports.

    The inducer LLM is not told what PoC prompt produced the failures, nor
    how that prompt was obtained.
    """
    parts = [

        "I asked an LLM to analyze the exploitability of some 3GPP Diameter field paths.",
        "However, the LLM-generated exploitability analysis did not pass expert review.",
        "I believe the failures come from the LLM not knowing enough protocol context about each target field.", 

        "",
        "For each example below I show the target field, the LLM-generated writeup, and the ground-truth writeup.",
        "",
    ]
    _append_failure_pairs(parts, failed_records, input_override_dir, record_mode)
    if any(record.get("validation_response") for record in failed_records):
        parts.extend(
            [
                "Below is validation feedback explaining why the generated reports still need prompt refinement.",
                "",
            ]
        )
        for idx, record in enumerate(failed_records, 1):
            feedback = record.get("validation_response", "")
            if record_mode == "minimal":
                feedback = _clip_text(feedback, 30000, "validation feedback")
            parts.extend(
                [
                    f"=== Example {idx}: Validation Feedback ===",
                    feedback,
                    "",
                ]
            )
    parts.extend(
        [
            "Your task is to infer a general protocol evidence-collection prompt from these feedbacks. ",
            "Given any Diameter field path as input, this prompt should instruct an LLM to search all the relevant 3GPP specifications and collect needed protocol context related to this field path for exploitability analysis and PoC construction, ",
            "so that the generated context is sufficient to support reports reproducing the ground-truth reports. ",
            "The prompt must be reusable on unseen Diameter field paths. ",
            "",
            "Output only the inferred prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_prompt_induction_failures_only(
    failed_records: List[Dict],
    input_override_dir: str = None,
    record_mode: str = "full",
) -> str:
    """Infer p_evi using only failed LLM-generated seed reports."""
    parts = [
        "I asked an LLM to analyze the exploitability of some 3GPP Diameter field paths.",
        "However, the LLM-generated exploitability analysis did not pass expert review.",
        "I believe the failures come from the LLM not knowing enough protocol context about each target field.", 
        "",
        "For each example below I show the target field and the LLM-generated writeup.",
        "",
    ]
    _append_failure_pairs(
        parts,
        failed_records,
        input_override_dir,
        record_mode,
        include_ground_truth=False,
    )
    parts.extend(
        [
            "Your task is to infer a general protocol evidence-collection prompt from these feedbacks. ",
            "Given any Diameter field path as input, this prompt should instruct an LLM to search all the relevant 3GPP specifications and collect needed protocol context related to this field path for exploitability analysis and PoC construction, ",
            "so that the generated context is sufficient to support reports reproducing the ground-truth reports. ",
            "The prompt must be reusable on unseen Diameter field paths. ",
            "",
            "Output only the inferred prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_prompt_induction_with_poc(
    failed_records: List[Dict],
    instruction: str,
    input_override_dir: str = None,
    record_mode: str = "full",
) -> str:
    """Infer p_evi from seed reports and the p_exp that produced them."""
    instr_text = (
        _clip_text(instruction, 10000, "PoC prompt")
        if record_mode == "minimal"
        else instruction
    )
    parts = [
        "I asked an LLM to analyze the exploitability of some 3GPP Diameter field paths.",
        "The LLM followed the exploitability-analysis prompt, p_exp, to analyze the target field paths.",
        "However, the LLM-generated exploitability analysis did not pass expert review.", 
        "I believe the failures come from the LLM not knowing enough protocol context about each target field.", 
        "",
        "For each example below I show the target field, the exploitability-analysis prompt p_exp, the LLM-generated writeup, and the ground-truth writeup.",
        "",
        "=== Exploitability-Analysis Prompt ===",
        instr_text,
        "",

    ]
    _append_failure_pairs(parts, failed_records, input_override_dir, record_mode)
    parts.extend(
        [
            "Your task is to infer a general protocol evidence-collection prompt from these feedbacks. ",
            "Given any Diameter field path as input, this prompt should instruct an LLM to search all the relevant 3GPP specifications and collect needed protocol context related to this field path for exploitability analysis and PoC construction, ",
            "so that the generated context is sufficient to support reports reproducing the ground-truth reports. ",
            "The prompt must be reusable on unseen Diameter field paths. ",
            "",
            "Output only the inferred prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_prompt_construction_from_enriched_failures(
    failed_records: List[Dict],
    support_samples: List[Sample],
    instruction: str,
    previous_context_prompt: str,
    round_index: int,
    include_previous_context_prompt: bool = True,
    input_override_dir: str = None,
    record_mode: str = "full",
) -> str:
    """Refine p_evi using collected context and failed seed reports."""
    instr_text = (
        _clip_text(instruction, 10000, "current PoC-generation prompt")
        if record_mode == "minimal"
        else instruction
    )
    ctx_prompt_text = ""
    if include_previous_context_prompt:
        ctx_prompt_text = (
            _clip_text(previous_context_prompt, 10000, "previous context prompt")
            if record_mode == "minimal"
            else previous_context_prompt
        )

    parts = [
        "I asked an LLM to analyze the exploitability of some 3GPP Diameter fields.",
        "The LLM followed the exploitability-analysis prompt, p_exp, to analyze the target field and its protocol context.",
        "However, the LLM-generated exploitability analysis did not pass expert review.",
        "I believe the failures come from the LLM not knowing enough protocol context about each target field.",
        "",
        "=== Exploitability-Analysis Prompt ===",
        instr_text,
        "",
    ]
    if include_previous_context_prompt:
        parts.extend(
            [
                "The protocol context shown in each example was collected by the current evidence-collection prompt shown below.",
                "",
                "=== Current Context-Collection Prompt ===",
                ctx_prompt_text,
                "",
            ]
        )
    else:
        parts.append("")
    parts.extend(
        [
            "For each example below I show:",
            "1. the target field,",
            "2. the protocol context collected,",
            "3. the report generated from that target field plus protocol context,",
            "4. the ground-truth report.",
            "",
        ]
    )

    for idx, record in enumerate(failed_records, 1):
        sample = record["sample"]
        display_label = _display_label(sample.label)
        original_input = build_input_for_case(sample)
        collected_context = record.get("collected_context", "")
        generated = record.get("generated_report", "")
        reference = sample.content
        if record_mode == "minimal":
            original_input = _clip_text(original_input, 10000, "original target field input")
            collected_context = _clip_text(collected_context, 10000, "collected context")
            generated = _clip_text(generated, 10000, "generated report")
            reference = _clip_text(reference, 10000, "ground-truth report")
        parts.extend(
            [
                f"=== Example {idx}: Diameter field ({display_label}) ===",
                original_input,
                "",
                f"=== Example {idx}: Protocol Context ===",
                collected_context or "[No context was collected or the context was empty.]",
                "",
                f"=== Example {idx}: Failed LLM-Generated Report===",
                generated,
                "",
                f"=== Example {idx}: Ground-truth Expert-Written Report ===",
                reference,
                "",
            ]
        )

    parts.extend(
        [
           "Your task is to infer a general protocol evidence-collection prompt from these feedbacks. "
           "Given any Diameter field path as input, this prompt should instruct an LLM to search all the relevant 3GPP specifications and collect needed protocol context related to this field path for exploitability analysis and PoC construction, "
           "so that the generated context is sufficient to support reports reproducing the ground-truth reports. "
           "The prompt must be reusable on unseen Diameter field paths. "
           "",
           "Output only the inferred prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_preparation_prompt(
    context_prompt: str,
    sample_input: str,
    spec_name: str = None,
    spec_text: str = None,
) -> str:
    spec_block = ""
    grounding = (
        "Use your protocol knowledge and the context-collection instructions above. "
    )
    if spec_name and spec_text:
        spec_block = f"\n\nBelow is the relevant specification ({spec_name}):\n\n{spec_text}\n"
        grounding = (
            "Ground the result in the specification text. If details cannot be verified "
            "from the document, leave them as unknown or placeholders."
        )

    return f"""Below is the target-field information:

{sample_input}

Use the following context-collection instructions to analyze the target above now.

{context_prompt}
{spec_block}

{grounding}

Output only the enriched context."""


def _protocol_description(samples: List[Sample]) -> str:
    interfaces = sorted({s.interface for s in samples})
    if interfaces == ["s6a"] or interfaces == ["cx"] or interfaces == ["sh"]:
        return f"Diameter {interfaces[0].upper()} protocol analysis"
    if len(interfaces) == 1:
        return f"{interfaces[0].upper()} protocol analysis"
    return "multi-protocol security analysis"


def _field_label(samples: List[Sample]) -> str:
    labels = {s.target_type for s in samples}
    if len(labels) == 1:
        return next(iter(labels))
    return "target-field"


def _comparison_scope(records: List[Dict]) -> str:
    labels = {record["sample"].label for record in records}
    if labels == {"ATTACK"}:
        return "the exploitable example" if len(records) == 1 else "the exploitable examples"
    if labels == {"SAFE"}:
        return "the non-exploitable example" if len(records) == 1 else "the non-exploitable examples"
    return "both the exploitable and non-exploitable examples"


def _clip_text(text: str, max_chars: int, label: str) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return (
        text[:max_chars].rstrip()
        + f"\n\n[TRUNCATED: omitted {omitted} characters from {label} to keep the prompt within the configured length budget.]"
    )
