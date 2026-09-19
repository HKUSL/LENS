from __future__ import annotations

from typing import Dict, List, Optional

from .samples import Sample, build_input_for_case


def build_poc_prompt_construction_prompt(
    samples: List[Sample],
    input_override_dir: Optional[str] = None,
    record_mode: str = "full",
) -> str:
    protocol_desc = protocol_description(samples)
    field_label = field_label_for_samples(samples)
    parts = [
        (
            f"You are given input-output examples for {protocol_desc}. "
            f"Each input describes a target {field_label} together with protocol context. "
            "Each output is an expert-written security analysis report, either a PoC report "
            "for an exploitable target or a safety report for a non-exploitable target. "
            "Infer the general instruction that maps inputs to such outputs. "
            f"The inferred instruction will be used as a prompt to analyze unseen {field_label}s. "
            "Output only the inferred instruction."
        ),
        "",
    ]
    compact = record_mode == "minimal"
    for i, sample in enumerate(samples, 1):
        sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
        sample_output = sample.content
        if compact:
            sample_input = clip_text(sample_input, 5000, "sample input")
            sample_output = clip_text(sample_output, 4000, "sample output")
        parts.extend(
            [
                f"Input {i} ({sample.label}):",
                sample_input,
                f"Output {i} ({sample.label}):",
                sample_output,
                "",
            ]
        )
    parts.append("Output only the instruction.")
    return "\n".join(parts)


def build_context_prompt_induction_with_poc(
    failed_records: List[Dict],
    instruction: str,
    input_override_dir: Optional[str] = None,
    record_mode: str = "full",
) -> str:
    samples = [record["sample"] for record in failed_records]
    protocol_desc = protocol_description(samples)
    field_label = field_label_for_samples(samples)
    instr_text = clip_text(instruction, 10000, "PoC prompt") if record_mode == "minimal" else instruction
    parts = [
        f"I asked an LLM to analyze target {field_label}s for {protocol_desc}.",
        "The LLM followed the exploitability-analysis prompt shown below.",
        "But the generated reports failed or were incomplete in my test environment.",
        f"I believe the failures come from missing protocol context about each target {field_label}.",
        "",
        "=== Exploitability-Analysis Prompt ===",
        instr_text,
        "",
        "For each example below I show the target information, the LLM's generated report, and the ground-truth report.",
        "",
    ]
    append_failure_records(parts, failed_records, input_override_dir, record_mode)
    parts.extend(
        [
            "Your task is to write a general context-collection prompt.",
            (
                f"Given any target {field_label} as input, this prompt should instruct an LLM "
                "to search relevant specifications or documents and collect the protocol context "
                "needed for exploitability analysis and PoC message construction."
            ),
            "The context should cover field semantics, valid values, dependencies on surrounding fields, state-machine or behavior effects, and implementation evidence when relevant.",
            "The generated context should be sufficient to support reports matching the ground-truth reports.",
            f"The prompt must be reusable on unseen target {field_label}s.",
            "",
            "Output only the prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_prompt_from_enriched_failures(
    failed_records: List[Dict],
    instruction: str,
    previous_context_prompt: str,
    include_previous_context_prompt: bool = True,
    record_mode: str = "full",
) -> str:
    samples = [record["sample"] for record in failed_records]
    protocol_desc = protocol_description(samples)
    field_label = field_label_for_samples(samples)
    instr_text = (
        clip_text(instruction, 10000, "current PoC-generation prompt")
        if record_mode == "minimal"
        else instruction
    )
    ctx_prompt_text = (
        clip_text(previous_context_prompt, 10000, "previous context prompt")
        if record_mode == "minimal"
        else previous_context_prompt
    )
    parts = [
        f"I asked an LLM to analyze target {field_label}s for {protocol_desc}.",
        "The LLM followed the exploitability-analysis prompt shown below.",
        (
            "Before analysis, I also used the context-collection prompt shown below to collect protocol context."
            if include_previous_context_prompt
            else "Before analysis, I also collected protocol context for each target."
        ),
        "Then I gave the target information plus the collected context to the exploitability-analysis prompt.",
        "But the generated reports still failed or were incomplete in my test environment.",
        "I believe the context-collection prompt did not ask for enough of the right protocol facts, or did not ask for them explicitly enough.",
        "",
        "=== Exploitability-Analysis Prompt ===",
        instr_text,
        "",
    ]
    if include_previous_context_prompt:
        parts.extend(["=== Current Context-Collection Prompt ===", ctx_prompt_text, ""])
    parts.extend(
        [
            "For each example below I show the original target information, the collected context, the generated report, and the ground-truth report.",
            "",
        ]
    )
    for idx, record in enumerate(failed_records, 1):
        sample = record["sample"]
        original_input = build_input_for_case(sample)
        collected_context = record.get("collected_context", "")
        generated = record.get("generated_report", "")
        reference = sample.content
        if record_mode == "minimal":
            original_input = clip_text(original_input, 10000, "original target information")
            collected_context = clip_text(collected_context, 10000, "collected context")
            generated = clip_text(generated, 10000, "generated report")
            reference = clip_text(reference, 10000, "ground-truth report")
        parts.extend(
            [
                f"=== Example {idx}: Target {field_label} ({sample.label}) ===",
                original_input,
                "",
                f"=== Example {idx}: Collected Context ===",
                collected_context or "[No context was collected or the context was empty.]",
                "",
                f"=== Example {idx}: Generated Report ===",
                generated,
                "",
                f"=== Example {idx}: Ground-truth Report ===",
                reference,
                "",
            ]
        )
    parts.extend(
        [
            "Your task is to write a general context-collection prompt.",
            (
                f"Given any target {field_label} as input, this prompt should instruct an LLM "
                "to search relevant specifications or documents and collect the protocol context "
                "needed for exploitability analysis and PoC message construction."
            ),
            "The prompt must be reusable on unseen targets without any context provided.",
            "",
            "Output only the prompt.",
        ]
    )
    return "\n".join(parts)


def build_context_preparation_prompt(context_prompt: str, sample_input: str) -> str:
    return f"""Below is the target information:

{sample_input}

Use the following context-collection instructions to analyze the target above now.

{context_prompt}

Use relevant specifications or documents. If details cannot be verified, leave them as unknown or placeholders.

Output only the enriched context."""


def build_exploit_assessment_prompt(sample_input: str, instruction: str) -> str:
    return f"{sample_input.rstrip()}\n\n=== Instruction ===\n\n{instruction.strip()}"


def build_websearch_nudge(sample: Optional[Sample] = None) -> str:
    protocol = protocol_description([sample]) if sample else "the target protocol"
    return (
        "# Tool usage requirement\n"
        f"You have a `web_search` tool. Use it to search relevant specifications or documents for {protocol}. "
        "Focus on field semantics, valid values, dependencies, behavior/state effects, and implementation evidence when relevant. "
        "Cite consulted URLs as `Sources:`."
    )


def protocol_description(samples: List[Sample]) -> str:
    interfaces = sorted({s.interface for s in samples if s})
    if not interfaces:
        return "protocol security analysis"
    if all(i in {"s6a", "s6d", "cx", "sh"} for i in interfaces):
        if len(interfaces) == 1:
            return f"Diameter {interfaces[0].upper()} protocol analysis"
        return "Diameter protocol analysis"
    if len(interfaces) == 1:
        return {
            "n1": "5G-NAS protocol analysis",
            "sip": "SIP protocol analysis",
            "mqtt": "MQTT protocol analysis",
            "coap": "CoAP protocol analysis",
            "oci": "OCI Runtime Spec analysis",
            "sle": "CCSDS-SLE protocol analysis",
            "tc": "CCSDS-TC/SDLS protocol analysis",
            "wayland": "Wayland protocol analysis",
            "amqp": "AMQP protocol analysis",
            "bacnet": "BACnet protocol analysis",
            "bgp": "BGP protocol analysis",
            "bgp_evpn": "BGP EVPN protocol analysis",
            "bgp_flowspec": "BGP FlowSpec protocol analysis",
            "cwmp": "CWMP/TR-069 protocol analysis",
            "dbus": "D-Bus protocol analysis",
            "dhcp": "DHCP protocol analysis",
            "dns": "DNS protocol analysis",
            "fuse": "FUSE protocol analysis",
            "http2": "HTTP/2 protocol analysis",
            "modbus": "Modbus protocol analysis",
            "radius": "RADIUS protocol analysis",
            "rtsp": "RTSP protocol analysis",
            "snmp": "SNMP protocol analysis",
            "tls13": "TLS 1.3 protocol analysis",
        }.get(interfaces[0], f"{interfaces[0].upper()} protocol analysis")
    return "multi-protocol security analysis"


def field_label_for_samples(samples: List[Sample]) -> str:
    labels = {s.target_type for s in samples if s and s.target_type}
    if len(labels) == 1:
        return next(iter(labels))
    return "field"


def append_failure_records(
    parts: List[str],
    failed_records: List[Dict],
    input_override_dir: Optional[str],
    record_mode: str,
) -> None:
    field_label = field_label_for_samples([record["sample"] for record in failed_records])
    for idx, record in enumerate(failed_records, 1):
        sample = record["sample"]
        sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
        reference = sample.content
        generated = record.get("generated_report", "")
        if record_mode == "minimal":
            sample_input = clip_text(sample_input, 4000, "target information")
            reference = clip_text(reference, 3000, "ground-truth report")
            generated = clip_text(generated, 3000, "generated report")
        parts.extend(
            [
                f"=== Example {idx}: Target {field_label} ({sample.label}) ===",
                sample_input,
                "",
                f"=== Example {idx}: Generated Report ===",
                generated,
                "",
                f"=== Example {idx}: Ground-truth Report ===",
                reference,
                "",
            ]
        )


def clip_text(text: str, max_chars: int, label: str) -> str:
    if len(text) <= max_chars:
        return text
    omitted = len(text) - max_chars
    return (
        text[:max_chars].rstrip()
        + f"\n\n[TRUNCATED: omitted {omitted} characters from {label} to keep the prompt within the configured length budget.]"
    )
