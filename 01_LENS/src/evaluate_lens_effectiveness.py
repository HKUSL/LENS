"""Evaluate the paper-facing LENS configurations on the Diameter dataset.

The command-line interface and output directories use the configuration names
reported in the paper. Each configuration records per-field responses,
classification metrics, token usage, and a manual-validation rubric.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .baselines import (
    build_few_shot_prompt,
    build_poc_context_prompt,
    build_spec_context_prompt,
    build_zero_shot_prompt,
)
from .common import EVAL_DIR, ensure_dir, file_ready, read_json, read_text, timestamp, write_json, write_text
from .llm import LLMRunner
from .parsing import parse_classification
from .pipeline import _generate_meaningful_context  # noqa: pipeline reuse
from .prompts import (
    build_context_preparation_prompt,
    build_context_prompt_induction_failures_only,
    build_context_prompt_induction_minimal,
    build_context_prompt_induction_with_poc,
    build_exploit_assessment_prompt,
    build_poc_prompt_construction_prompt,
)
from .samples import (
    Sample,
    build_input_for_case,
    load_target_paths_file,
    parse_seed_examples,
)
from .spec_docs import find_spec_doc, load_spec_text


DEFAULT_EVALUATION_DATASET = os.path.join(
    EVAL_DIR, "data", "diameter", "evaluation_dataset.csv"
)
DEFAULT_SEED_EXAMPLES_FILE = os.path.join(
    EVAL_DIR, "data", "diameter", "seed_examples.md"
)


def _default_induced_prompt_dir(service: str) -> str:
    return os.path.join(
        EVAL_DIR, "output", service, "prompt_construction",
        "m01", "m01_a04_s14", "round_00",
    )


PAPER_CONFIGURATIONS: Dict[str, Dict[str, str]] = {
    "lens": {
        "method_id": "M7c",
        "label": "LENS",
    },
    "simple_prompt": {
        "method_id": "M1",
        "label": "Simple Prompt",
    },
    "few_shot_examples": {
        "method_id": "M2",
        "label": "Few-shot Examples",
    },
    "initial_pexp": {
        "method_id": "M3",
        "label": "Initial p_exp",
    },
    "keyword_retrieval": {
        "method_id": "M4",
        "label": "Keyword Retrieval",
    },
    "field_relevant_retrieval": {
        "method_id": "M5a",
        "label": "Field-Relevant Retrieval",
    },
    "exploitability_relevant_retrieval": {
        "method_id": "M5b",
        "label": "Exploitability-Relevant Retrieval",
    },
    "initial_pexp_initial_pevi": {
        "method_id": "M6c",
        "label": "Initial p_exp + Initial p_evi",
    },
    "refined_pexp_refined_pevi": {
        "method_id": "M7c",
        "label": "Refined p_exp + Refined p_evi",
    },
    "llm_generated_writeup_only": {
        "method_id": "M70",
        "label": "LLM-Generated Writeup Only",
    },
    "add_expert_written_writeup": {
        "method_id": "M7b",
        "label": "Add Expert-Written Writeup",
    },
    "add_analysis_history": {
        "method_id": "M7c",
        "label": "Add Analysis History",
    },
}


def _resolve_configuration(value: str) -> Dict[str, str]:
    if value in PAPER_CONFIGURATIONS:
        config = PAPER_CONFIGURATIONS[value]
        return {
            "name": value,
            "label": config["label"],
            "method_id": config["method_id"],
        }
    raise ValueError(value)


# Methods that need the induced PoC instruction.
_POC_METHODS = {
    "M3", "M4", "M5a", "M5b",
    "M6c", "M70", "M7b", "M7c",
}
# Methods that wrap target_input with an additional protocol-context block.
_CTX_METHODS = {
    "M4", "M5a", "M5b",
    "M6c", "M70", "M7b", "M7c",
}
# Methods that induce their own ctx-collection prompt on the fly.
_INDUCED_CTX_METHODS = {
    "M6c", "M70", "M7b", "M7c",
}
_M6_REUSE_BASE = {
    "M6c": "M7c",
}
# Methods that generate per-target context via the web_search tool.
_WEBSEARCH_CTX_METHODS = {
    "M5a", "M5b",
    "M6c", "M70", "M7b", "M7c",
}

_INDUCER_VARIANT = {
    "M70": "failures_only",
    "M7b": "minimal",
    "M7c": "with_poc",
}
_INDUCER_OUTPUT_NAMES = {
    "failures_only": "llm_generated_writeup_only",
    "minimal": "add_expert_written_writeup",
    "with_poc": "add_analysis_history",
}

_ARTIFACT_LOCKS: Dict[Tuple[str, str], threading.Lock] = {}
_ARTIFACT_LOCKS_GUARD = threading.Lock()


def _artifact_lock(output_dir: str, variant: str) -> threading.Lock:
    key = (os.path.abspath(output_dir), variant)
    with _ARTIFACT_LOCKS_GUARD:
        lock = _ARTIFACT_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ARTIFACT_LOCKS[key] = lock
        return lock


WEBSEARCH_NUDGE = (
    "# Tool usage requirement\n"
    "You have a `web_search` tool. Use it to search relevant 3GPP specifications for the information requested by the context-collection prompt above. "
    "Cite consulted URLs as `Sources:`."
)

ANALYSIS_WEBSEARCH_NUDGE = (
    "# Tool usage requirements\n"
    "You have a `web_search` tool. Only search in 3GPP specifications. "
)


def _read_prompt(prompt_dir: str, kind: str) -> str:
    """Read final_instruction.txt or final_context_prompt.txt.

    Supports two layouts:
    1. ``<prompt_dir>/final_instruction.txt`` and ``final_context_prompt.txt``
       (the converged support-set root layout).
    2. ``<prompt_dir>/poc_prompt_construction/final_instruction.txt`` and
       ``<prompt_dir>/context_prompt_construction/final_context_prompt.txt``
       (the per-round layout used when targeting a specific round_NN/).
    """
    if kind == "instruction":
        candidates = [
            os.path.join(prompt_dir, "final_instruction.txt"),
            os.path.join(prompt_dir, "poc_prompt_construction", "final_instruction.txt"),
        ]
    elif kind == "context":
        candidates = [
            os.path.join(prompt_dir, "final_context_prompt.txt"),
            os.path.join(prompt_dir, "context_prompt_construction", "final_context_prompt.txt"),
        ]
    else:
        raise ValueError(kind)
    for path in candidates:
        if os.path.exists(path):
            return read_text(path)
    raise FileNotFoundError(f"missing {kind} prompt under {prompt_dir}: tried {candidates}")


def _load_seeds(seed_examples_file: str, attack_nums: List[int], safe_nums: List[int]) -> List[Sample]:
    attacks = parse_seed_examples(seed_examples_file, label="ATTACK", attack_side="all")
    safes = parse_seed_examples(seed_examples_file, label="SAFE")
    pool = {s.number: s for s in attacks + safes}
    out: List[Sample] = []
    for n in attack_nums + safe_nums:
        if n in pool:
            out.append(pool[n])
    return out


def _wrap_with_context(target_input_minimal: str, ctx_text: Optional[str]) -> str:
    ctx_text = (ctx_text or "").strip()
    if not ctx_text:
        return target_input_minimal
    return (
        f"{target_input_minimal.rstrip()}\n\n===Protocol Evidence===\n"
        f"{ctx_text}\n"
    )


def _build_method_prompt(
    method: str,
    target_input_minimal: str,
    seeds: List[Sample],
    induced_instruction: Optional[str],
    enriched_input: Optional[str],
) -> str:
    if method == "M1":
        return build_zero_shot_prompt(target_input_minimal)
    if method == "M2":
        return build_few_shot_prompt(target_input_minimal, seeds)
    if method == "M3":
        return build_exploit_assessment_prompt(target_input_minimal, induced_instruction or "")
    if method in _CTX_METHODS:
        # Present protocol context as evidence after the analysis instruction.
        base = build_exploit_assessment_prompt(
            target_input_minimal, induced_instruction or ""
        )
        ctx = (enriched_input or "").strip()
        if ctx:
            return f"{base}\n\n===Protocol Evidence===\n{ctx}\n"
        return base
    raise ValueError(method)


def _prepare_induced_context(
    runner: LLMRunner,
    context_prompt: str,
    target_input: str,
    cache_path: str,
    force: bool,
) -> Optional[str]:
    if not force and file_ready(cache_path, min_size=30):
        return read_text(cache_path)
    prompt = build_context_preparation_prompt(context_prompt, target_input)
    response = _generate_meaningful_context(runner, prompt, target_input)
    if response:
        write_text(cache_path, response)
    return response


def _prepare_induced_context_websearch(
    runner: LLMRunner,
    context_prompt: str,
    target_input: str,
    cache_path: str,
    force: bool,
    search_log_path: Optional[str] = None,
) -> Optional[str]:
    """Like ``_prepare_induced_context`` but calls /responses with web_search.

    Also writes the list of web_search_call items as a sidecar JSON file
    (``search_log_path``) so we can audit which URLs the model consulted.
    """
    if not force and file_ready(cache_path, min_size=30):
        return read_text(cache_path)
    prompt = build_context_preparation_prompt(context_prompt, target_input)
    result = runner.generate_with_websearch(prompt, nudge=WEBSEARCH_NUDGE)
    if not result or not result.get("text"):
        return None
    write_text(cache_path, result["text"])
    if search_log_path:
        write_json(search_log_path, {
            "search_calls": result.get("search_calls", []),
            "usage": result.get("usage", {}),
            "elapsed_s": result.get("elapsed_s"),
        })
    return result["text"]


def _prepare_spec_context_websearch(
    runner: LLMRunner,
    target_input: str,
    cache_path: str,
    force: bool,
    search_log_path: Optional[str] = None,
) -> Optional[str]:
    """Collect field-relevant protocol context with web search."""
    if not force and file_ready(cache_path, min_size=30):
        return read_text(cache_path)
    prompt = build_spec_context_prompt(target_input)
    result = runner.generate_with_websearch(prompt, nudge=WEBSEARCH_NUDGE)
    if not result or not result.get("text"):
        return None
    write_text(cache_path, result["text"])
    if search_log_path:
        write_json(search_log_path, {
            "search_calls": result.get("search_calls", []),
            "usage": result.get("usage", {}),
            "elapsed_s": result.get("elapsed_s"),
        })
    return result["text"]


def _prepare_poc_context_websearch(
    runner: LLMRunner,
    target_input: str,
    cache_path: str,
    force: bool,
    search_log_path: Optional[str] = None,
) -> Optional[str]:
    """Collect exploitability-relevant protocol context with web search."""
    if not force and file_ready(cache_path, min_size=30):
        return read_text(cache_path)
    prompt = build_poc_context_prompt(target_input)
    result = runner.generate_with_websearch(prompt, nudge=WEBSEARCH_NUDGE)
    if not result or not result.get("text"):
        return None
    write_text(cache_path, result["text"])
    if search_log_path:
        write_json(search_log_path, {
            "search_calls": result.get("search_calls", []),
            "usage": result.get("usage", {}),
            "elapsed_s": result.get("elapsed_s"),
        })
    return result["text"]


def _prepare_spec_context(sample: Sample, cache_path: str, force: bool) -> Optional[str]:
    """Load the per-AVP standard doc text. Returns None if no doc exists."""
    if not force and file_ready(cache_path, min_size=30):
        return read_text(cache_path)
    text = load_spec_text(sample)
    if not text:
        return None
    write_text(cache_path, text)
    return text


def _load_seed_failed_records(seeds: List[Sample], round0_dir: str) -> List[Dict]:
    """Load the round_00 exploit-assessment responses for each seed.

    These are the 'failed' reports that drive context-prompt induction. We
    expect <round0_dir>/exploit_assessment/case<NN>_*_response.txt
    for each seed sample.
    """
    assessment_dir = os.path.join(round0_dir, "exploit_assessment")
    records: List[Dict] = []
    for seed in seeds:
        prefix = f"case{seed.number:02d}_"
        match = None
        if os.path.isdir(assessment_dir):
            for name in sorted(os.listdir(assessment_dir)):
                if name.startswith(prefix) and name.endswith("_response.txt"):
                    match = os.path.join(assessment_dir, name)
                    break
        if not match:
            raise FileNotFoundError(
                f"missing round_00 failed report for seed {seed.number} "
                f"(expected {prefix}*_response.txt under {assessment_dir})"
            )
        records.append({"sample": seed, "generated_report": read_text(match)})
    return records


def _ensure_m6_round2_artifacts(
    runner: LLMRunner,
    variant: str,
    seeds: List[Sample],
    output_dir: str,
    seed_failure_dir: str,
    force: bool,
    workers: int = 1,
) -> Tuple[str, str]:
    """Build the inferred evidence prompt and refined analysis prompt.

    Round 0 (already on disk):
        - <seed_failure_dir>/poc_prompt_construction/final_instruction.txt
          (baseline PoC prompt, induced from raw seed inputs + GT reports).
        - <seed_failure_dir>/exploit_assessment/case<NN>_*_response.txt
          (failed reports produced by the baseline PoC prompt on seeds).

    The Initial p_exp + Initial p_evi configuration keeps the initial analysis
    prompt. Other retained configurations return the refined analysis prompt.
    """
    if variant in _M6_REUSE_BASE:
        base_variant = _M6_REUSE_BASE[variant]
        ctx_prompt, _ = _ensure_m6_round2_artifacts(
            runner=runner,
            variant=base_variant,
            seeds=seeds,
            output_dir=output_dir,
            seed_failure_dir=seed_failure_dir,
            force=force,
            workers=workers,
        )
        round0_poc_path = os.path.join(
            seed_failure_dir, "poc_prompt_construction", "final_instruction.txt"
        )
        if not os.path.exists(round0_poc_path):
            raise FileNotFoundError(
                f"missing round_00 PoC prompt for {variant}: {round0_poc_path}"
            )
        return ctx_prompt, read_text(round0_poc_path)

    with _artifact_lock(output_dir, variant):
        return _ensure_base_round2_artifacts_locked(
            runner=runner,
            variant=variant,
            seeds=seeds,
            output_dir=output_dir,
            seed_failure_dir=seed_failure_dir,
            force=force,
            workers=workers,
        )


def _ensure_base_round2_artifacts_locked(
    runner: LLMRunner,
    variant: str,
    seeds: List[Sample],
    output_dir: str,
    seed_failure_dir: str,
    force: bool,
    workers: int = 1,
) -> Tuple[str, str]:
    inducer = _INDUCER_VARIANT.get(variant)
    if not inducer:
        raise ValueError(variant)
    cache_dir = ensure_dir(
        os.path.join(output_dir, "_induced_ctx", _INDUCER_OUTPUT_NAMES[inducer])
    )

    round0_poc_path = os.path.join(
        seed_failure_dir, "poc_prompt_construction", "final_instruction.txt"
    )
    if not os.path.exists(round0_poc_path):
        raise FileNotFoundError(
            f"missing round_00 PoC prompt for {variant}: {round0_poc_path}"
        )
    round0_poc_prompt = read_text(round0_poc_path)
    failed_records = _load_seed_failed_records(seeds, seed_failure_dir)

    ctx_prompt_path = os.path.join(cache_dir, "round1_ctx_prompt.txt")
    if not force and file_ready(ctx_prompt_path, min_size=30):
        ctx_prompt = read_text(ctx_prompt_path)
    else:
        if inducer == "failures_only":
            induction_prompt = build_context_prompt_induction_failures_only(
                failed_records
            )
        elif inducer == "minimal":
            induction_prompt = build_context_prompt_induction_minimal(failed_records)
        elif inducer == "with_poc":
            induction_prompt = build_context_prompt_induction_with_poc(
                failed_records, round0_poc_prompt
            )
        else:
            raise ValueError(variant)
        write_text(
            os.path.join(cache_dir, "round1_ctx_induction_input.txt"),
            induction_prompt,
        )
        print(f"  [{variant}] inducing round-1 ctx prompt ...")
        ctx_prompt = runner.generate(induction_prompt)
        if not ctx_prompt:
            raise RuntimeError(
                f"empty round-1 ctx prompt for {variant}; last LLM error: {runner.last_error}"
            )
        write_text(ctx_prompt_path, ctx_prompt)

    enriched_dir = ensure_dir(os.path.join(cache_dir, "enriched_seeds"))
    use_websearch = variant in _WEBSEARCH_CTX_METHODS

    def enrich_seed(seed: Sample) -> None:
        enriched_path = os.path.join(enriched_dir, f"{seed.input_key}_input.txt")
        if not force and file_ready(enriched_path, min_size=30):
            return
        target_input = build_input_for_case(seed)
        print(f"  [{variant}] enriching seed {seed.input_key}"
              f"{' (web_search)' if use_websearch else ''} ...")
        ctx_cache = os.path.join(cache_dir, f"_seed_ctx_{seed.input_key}.txt")
        if use_websearch:
            search_log = os.path.join(cache_dir, f"_seed_ctx_{seed.input_key}_searches.json")
            ctx_text = _prepare_induced_context_websearch(
                runner, ctx_prompt, target_input, ctx_cache, force, search_log
            )
        else:
            ctx_text = _prepare_induced_context(
                runner, ctx_prompt, target_input, ctx_cache, force
            )
        if not ctx_text:
            raise RuntimeError(
                f"empty enriched context for {variant}/{seed.input_key}"
            )
        write_text(enriched_path, _wrap_with_context(target_input, ctx_text))

    seed_workers = max(1, min(workers, len(seeds)))
    if seed_workers == 1:
        for seed in seeds:
            enrich_seed(seed)
    else:
        with ThreadPoolExecutor(max_workers=seed_workers) as pool:
            futures = [pool.submit(enrich_seed, seed) for seed in seeds]
            for fut in as_completed(futures):
                fut.result()

    round2_poc_path = os.path.join(cache_dir, "round2_poc_prompt.txt")
    if not force and file_ready(round2_poc_path, min_size=30):
        round2_poc_prompt = read_text(round2_poc_path)
    else:
        poc_induction_prompt = build_poc_prompt_construction_prompt(
            seeds, input_override_dir=enriched_dir
        )
        write_text(
            os.path.join(cache_dir, "round2_poc_induction_input.txt"),
            poc_induction_prompt,
        )
        print(f"  [{variant}] inducing round-2 PoC prompt ...")
        round2_poc_prompt = runner.generate(poc_induction_prompt)
        if not round2_poc_prompt:
            raise RuntimeError(
                f"empty round-2 PoC prompt for {variant}; last LLM error: {runner.last_error}"
            )
        write_text(round2_poc_path, round2_poc_prompt)

    return ctx_prompt, round2_poc_prompt


def _run_method(
    method: str,
    configuration_name: str,
    configuration_label: str,
    targets: List[Sample],
    seeds: List[Sample],
    output_dir: str,
    runner: LLMRunner,
    workers: int,
    induced_instruction: Optional[str],
    seed_failure_dir: Optional[str],
    shared_context_dir: str,
    force: bool,
    analysis_websearch: bool,
) -> List[Dict]:
    method_dir = ensure_dir(os.path.join(output_dir, configuration_name))
    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    # Resolve the context-collection and exploitability-analysis prompts.
    ctx_prompt_text: Optional[str] = None
    if method in _INDUCED_CTX_METHODS:
        if not seed_failure_dir:
            raise RuntimeError(f"{method} requires --seed-failure-dir or a default round_00 dir")
        ctx_prompt_text, induced_instruction = _ensure_m6_round2_artifacts(
            runner=runner,
            variant=method,
            seeds=seeds,
            output_dir=output_dir,
            seed_failure_dir=seed_failure_dir,
            force=force,
            workers=workers,
        )
        write_text(os.path.join(method_dir, "context_prompt_used.txt"), ctx_prompt_text)

    if method in _POC_METHODS:
        write_text(os.path.join(method_dir, "instruction_used.txt"), induced_instruction or "")

    spec_status: List[Dict] = []

    def process(sample: Sample) -> Dict:
        target_input = build_input_for_case(sample)
        prompt_path = os.path.join(method_dir, f"{sample.input_key}_prompt.txt")
        response_path = os.path.join(method_dir, f"{sample.input_key}_response.txt")

        def finish(
            response_text: str,
            status: str,
            spec_source: Optional[str] = None,
            analysis_search_log: Optional[str] = None,
        ) -> Dict:
            classification = parse_classification(response_text or "")
            with lock:
                completed[0] += 1
                extra = f"  ctx={spec_source}" if method == "M4" and spec_source else ""
                print(f"  [{completed[0]}/{len(targets)}] {configuration_name} {sample.input_key} "
                      f"{sample.label}->{classification} ({status}){extra}")
            return {
                "configuration": configuration_name,
                "configuration_label": configuration_label,
                "method_id": method,
                "number": sample.number,
                "input_key": sample.input_key,
                "label": sample.label,
                "interface": sample.interface,
                "message_full": sample.message_full,
                "target_path": sample.target_path,
                "classification": classification,
                "status": status,
                "response_file": os.path.basename(response_path),
                "analysis_websearch": analysis_websearch,
                "analysis_search_log": analysis_search_log,
            }

        if not force and file_ready(response_path, min_size=30):
            return finish(read_text(response_path), "skipped")

        enriched: Optional[str] = None
        spec_source = None

        if method == "M4":
            cache = os.path.join(
                shared_context_dir,
                f"keyword_retrieval_{sample.input_key}.txt",
            )
            enriched = _prepare_spec_context(sample, cache, force)
            spec_source = "spec_doc" if enriched else "none"
            spec_path = find_spec_doc(sample)
            spec_status.append({
                "input_key": sample.input_key,
                "message_full": sample.message_full,
                "target_path": sample.target_path,
                "spec_doc": os.path.basename(spec_path) if spec_path else None,
                "source": spec_source,
                "char_len": len(enriched or ""),
            })
        elif method == "M5a":
            cache = os.path.join(
                shared_context_dir,
                f"field_relevant_retrieval_{sample.input_key}.txt",
            )
            search_log = os.path.join(
                shared_context_dir,
                f"field_relevant_retrieval_{sample.input_key}_searches.json",
            )
            enriched = _prepare_spec_context_websearch(
                runner, target_input, cache, force, search_log,
            )
        elif method == "M5b":
            cache = os.path.join(
                shared_context_dir,
                f"exploitability_relevant_retrieval_{sample.input_key}.txt",
            )
            search_log = os.path.join(
                shared_context_dir,
                f"exploitability_relevant_retrieval_{sample.input_key}_searches.json",
            )
            enriched = _prepare_poc_context_websearch(
                runner, target_input, cache, force, search_log,
            )
        elif method in _INDUCED_CTX_METHODS:
            cache_method = _M6_REUSE_BASE.get(method, method)
            inducer = _INDUCER_VARIANT.get(cache_method)
            cache_name = (
                _INDUCER_OUTPUT_NAMES[inducer]
                if inducer
                else cache_method.lower()
            )
            cache = os.path.join(
                shared_context_dir, f"{cache_name}_{sample.input_key}.txt"
            )
            if method in _WEBSEARCH_CTX_METHODS:
                search_log = os.path.join(
                    shared_context_dir,
                    f"{cache_name}_{sample.input_key}_searches.json",
                )
                enriched = _prepare_induced_context_websearch(
                    runner, ctx_prompt_text or "", target_input, cache, force,
                    search_log,
                )
            else:
                enriched = _prepare_induced_context(
                    runner, ctx_prompt_text or "", target_input, cache, force
                )

        prompt = _build_method_prompt(
            method=method,
            target_input_minimal=target_input,
            seeds=seeds,
            induced_instruction=induced_instruction,
            enriched_input=enriched,
        )
        write_text(prompt_path, prompt)
        analysis_search_log = None
        if analysis_websearch:
            search_log_path = os.path.join(
                method_dir, f"{sample.input_key}_analysis_searches.json"
            )
            result = runner.generate_with_websearch(
                prompt,
                nudge=ANALYSIS_WEBSEARCH_NUDGE,
            )
            response = result.get("text", "") if result else ""
            status = "success_websearch" if response else "error"
            if result:
                write_json(search_log_path, {
                    "search_calls": result.get("search_calls", []),
                    "usage": result.get("usage", {}),
                    "elapsed_s": result.get("elapsed_s"),
                })
                analysis_search_log = os.path.basename(search_log_path)
        else:
            response = runner.generate(prompt)
            status = "success" if response else "error"
        if response:
            write_text(response_path, response)

        return finish(response or "", status, spec_source, analysis_search_log)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(process, sample) for sample in targets]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r["number"])
    results_path = os.path.join(method_dir, "results.json")
    write_json(results_path, results)
    if method == "M4" and spec_status:
        write_json(os.path.join(method_dir, "spec_doc_status.json"), spec_status)
    return results


def _confusion(results: List[Dict]) -> Dict:
    pred_labels = ["ATTACK", "SAFE", "UNKNOWN", "OTHER"]
    matrix = {"ATTACK": {p: 0 for p in pred_labels}, "SAFE": {p: 0 for p in pred_labels}}
    for r in results:
        gt = r["label"]
        if gt not in matrix:
            continue
        pred = r["classification"] if r["classification"] in pred_labels else "OTHER"
        matrix[gt][pred] += 1
    tp = matrix["ATTACK"]["ATTACK"]
    fn = matrix["ATTACK"]["SAFE"] + matrix["ATTACK"]["UNKNOWN"] + matrix["ATTACK"]["OTHER"]
    fp = matrix["SAFE"]["ATTACK"]
    tn = matrix["SAFE"]["SAFE"]
    total_atk = tp + fn
    total_safe = sum(matrix["SAFE"].values())
    return {
        "matrix": matrix,
        "total_atk": total_atk,
        "total_safe": total_safe,
        "reported_attack": tp + fp,
        "attack_recall": tp / total_atk if total_atk else None,
        "attack_precision": tp / (tp + fp) if (tp + fp) else None,
        "safe_recall": tn / total_safe if total_safe else None,
        "accuracy": (tp + tn) / (total_atk + total_safe) if (total_atk + total_safe) else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run paper-facing LENS configurations on a target dataset."
    )
    parser.add_argument(
        "--evaluation-dataset",
        default=DEFAULT_EVALUATION_DATASET,
        help="Target fields in CSV, JSON, or message-to-field text format.",
    )
    parser.add_argument("--seed-examples", default=DEFAULT_SEED_EXAMPLES_FILE)
    parser.add_argument("--induced-prompt-dir", default=None,
                        help="Directory containing the induced final_instruction.txt and "
                             "final_context_prompt.txt; shared by configurations that use inferred guidance. "
                             "Defaults to output/<service>/prompt_construction/m01/m01_a04_s14/round_00.")
    parser.add_argument("--seed-failure-dir", default=None,
                        help="Directory with the seed round_00 exploit_assessment responses "
                             "(used for evidence-guidance inference and prompt refinement). "
                             "Defaults to the sibling round_00 of --induced-prompt-dir.")
    parser.add_argument("--seed-attacks", default="4", help="Comma-separated ATTACK seed numbers for few-shot examples.")
    parser.add_argument("--seed-safes", default="14", help="Comma-separated SAFE seed numbers for few-shot examples.")
    parser.add_argument(
        "--configurations",
        dest="configurations",
        required=True,
        help="Comma-separated paper configuration names.",
    )
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument("--search-service", dest="search_service", default=None,
                        help="Route web_search calls to a DIFFERENT service than --service "
                             "(e.g. --service claude --search-service gemini). Plain "
                             "generate() still uses --service; only generate_with_websearch "
                             "is redirected. Defaults to --service.")
    parser.add_argument("--search-retries", dest="search_retries", type=int, default=None,
                        help="Max attempts for each web_search call "
                             "(default max(max_retries, 8)).")
    parser.add_argument("--max-retries", dest="max_retries", type=int, default=None,
                        help="Max attempts for each plain generate() call (default 5).")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument(
        "--configuration-workers",
        dest="configuration_workers",
        type=int,
        default=1,
        help="Number of configurations to run concurrently. Total LLM concurrency is roughly configuration-workers * workers.",
    )
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--include-numbers", default=None,
                        help="Comma-separated 'number' column values to keep "
                             "(e.g. '32,33,35'). Filters AFTER loading so that "
                             "input_key (valNNN) is preserved.")
    parser.add_argument(
        "--analysis-websearch",
        dest="analysis_websearch",
        action="store_true",
        default=None,
        help="Use web_search during final exploitability analysis, not only during context collection.",
    )
    parser.add_argument(
        "--no-analysis-websearch",
        dest="analysis_websearch",
        action="store_false",
        help="Disable web_search during final exploitability analysis.",
    )
    args = parser.parse_args()

    if args.induced_prompt_dir is None:
        args.induced_prompt_dir = _default_induced_prompt_dir(args.service)
    if args.seed_failure_dir is None:
        args.seed_failure_dir = os.path.normpath(
            os.path.join(args.induced_prompt_dir, "..", "round_00")
        )
    if args.analysis_websearch is None:
        args.analysis_websearch = args.service == "gpt5.4"

    targets = load_target_paths_file(args.evaluation_dataset)
    if args.include_numbers:
        keep = {int(s) for s in args.include_numbers.split(",") if s.strip()}
        before = len(targets)
        targets = [t for t in targets if t.number in keep]
        print(f"  filtered targets: {before} -> {len(targets)} (kept numbers={sorted(keep)})")
    seeds = _load_seeds(
        args.seed_examples,
        [int(s) for s in args.seed_attacks.split(",") if s.strip()],
        [int(s) for s in args.seed_safes.split(",") if s.strip()],
    )
    requested_configurations = [
        value.strip() for value in args.configurations.split(",") if value.strip()
    ]
    try:
        configurations = [
            _resolve_configuration(value) for value in requested_configurations
        ]
    except ValueError as exc:
        parser.error(
            f"unknown configuration: {exc.args[0]}; paper names: "
            + ", ".join(PAPER_CONFIGURATIONS)
        )
    configuration_names = [config["name"] for config in configurations]
    if len(configuration_names) != len(set(configuration_names)):
        parser.error("duplicate configurations resolve to the same paper-facing name")

    output_dir = args.output_dir or os.path.join(
        EVAL_DIR, "output", args.service, "method_evaluation", f"run_{timestamp()}"
    )
    ensure_dir(output_dir)
    shared_context_dir = ensure_dir(os.path.join(output_dir, "_shared_context"))
    resolved_search_service = LLMRunner(
        args.service,
        search_service_name=args.search_service,
    ).search_service_name

    induced_instruction = _read_prompt(args.induced_prompt_dir, "instruction")

    print("=" * 80)
    print("LENS configuration comparison")
    print(f"  targets: {len(targets)}")
    print(f"  few-shot seeds: ATTACK={args.seed_attacks}  SAFE={args.seed_safes}")
    print(f"  induced prompt dir: {args.induced_prompt_dir}")
    print(f"  seed failure dir: {args.seed_failure_dir}")
    print(f"  configurations: {[config['name'] for config in configurations]}")
    print(f"  output  : {output_dir}")
    print(f"  service (generate): {args.service}")
    print(f"  search service (web_search): {resolved_search_service}")
    print(f"  analysis web_search: {args.analysis_websearch}")
    print("=" * 80)

    all_results: Dict[str, List[Dict]] = {}
    per_configuration_stats: Dict[str, Dict] = {}
    started = time.time()

    def run_one_configuration(
        configuration: Dict[str, str],
    ) -> Tuple[str, List[Dict], Dict]:
        configuration_name = configuration["name"]
        configuration_label = configuration["label"]
        method_id = configuration["method_id"]
        runner = LLMRunner(args.service, search_service_name=resolved_search_service,
                           websearch_max_retries=args.search_retries,
                           max_retries=args.max_retries if args.max_retries else 5)
        t0 = time.time()
        results = _run_method(
            method=method_id,
            configuration_name=configuration_name,
            configuration_label=configuration_label,
            targets=targets,
            seeds=seeds,
            output_dir=output_dir,
            runner=runner,
            workers=args.workers,
            induced_instruction=induced_instruction,
            seed_failure_dir=args.seed_failure_dir,
            shared_context_dir=shared_context_dir,
            force=args.force,
            analysis_websearch=args.analysis_websearch,
        )
        stats = runner.get_stats()
        configuration_stats = {
            "configuration_label": configuration_label,
            "method_id": method_id,
            "calls": stats["calls"],
            "successes": stats["successes"],
            "failures": stats["failures"],
            "prompt_tokens": stats["prompt_tokens"],
            "completion_tokens": stats["completion_tokens"],
            "total_tokens": stats["total_tokens"],
            "elapsed_s": time.time() - t0,
            "confusion": _confusion(results),
        }
        return configuration_name, results, configuration_stats

    if args.configuration_workers <= 1:
        for configuration in configurations:
            name, results, stats = run_one_configuration(configuration)
            all_results[name] = results
            per_configuration_stats[name] = stats
    else:
        with ThreadPoolExecutor(max_workers=args.configuration_workers) as pool:
            futures = [
                pool.submit(run_one_configuration, configuration)
                for configuration in configurations
            ]
            for fut in as_completed(futures):
                name, results, stats = fut.result()
                all_results[name] = results
                per_configuration_stats[name] = stats

    elapsed = time.time() - started
    summary_path = os.path.join(output_dir, "evaluation_summary.json")
    token_stats_total = {
        "calls": sum(s["calls"] for s in per_configuration_stats.values()),
        "successes": sum(s["successes"] for s in per_configuration_stats.values()),
        "failures": sum(s["failures"] for s in per_configuration_stats.values()),
        "prompt_tokens": sum(s["prompt_tokens"] for s in per_configuration_stats.values()),
        "completion_tokens": sum(s["completion_tokens"] for s in per_configuration_stats.values()),
        "total_tokens": sum(s["total_tokens"] for s in per_configuration_stats.values()),
        "total_latency_s": sum(s["elapsed_s"] for s in per_configuration_stats.values()),
    }
    summary = {
        "configurations": configurations,
        "targets_total": len(targets),
        "seeds_attack": args.seed_attacks,
        "seeds_safe": args.seed_safes,
        "induced_prompt_dir": args.induced_prompt_dir,
        "seed_failure_dir": args.seed_failure_dir,
        "search_service": resolved_search_service,
        "configuration_workers": args.configuration_workers,
        "workers": args.workers,
        "per_configuration": per_configuration_stats,
        "elapsed_seconds": elapsed,
        "token_stats_total": token_stats_total,
        "output_dir": output_dir,
    }
    write_json(summary_path, summary)

    print("\n=== Evaluation summary ===")
    csv_path = os.path.join(output_dir, "evaluation_summary.csv")
    csv_fields = [
        "configuration", "configuration_label", "method_id",
        "reported_attack", "attack_recall", "attack_precision",
        "safe_recall", "accuracy", "calls", "prompt_tokens",
        "completion_tokens",
    ]
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fields)
        writer.writeheader()
        for configuration in configurations:
            name = configuration["name"]
            stats = per_configuration_stats[name]
            confusion = stats["confusion"]
            writer.writerow({
                "configuration": name,
                "configuration_label": configuration["label"],
                "method_id": configuration["method_id"],
                "reported_attack": confusion["reported_attack"],
                "attack_recall": _fmt(confusion["attack_recall"]),
                "attack_precision": _fmt(confusion["attack_precision"]),
                "safe_recall": _fmt(confusion["safe_recall"]),
                "accuracy": _fmt(confusion["accuracy"]),
                "calls": stats["calls"],
                "prompt_tokens": stats["prompt_tokens"],
                "completion_tokens": stats["completion_tokens"],
            })
            print(
                f"  {configuration['label']} ({name}): "
                f"accuracy={_fmt(confusion['accuracy']) or 'n/a'}"
            )
    print(f"\n  output: {output_dir}")
    print(f"  total tokens: {summary['token_stats_total']}")
    configuration_by_name = {
        configuration["name"]: configuration
        for configuration in configurations
    }
    _write_rubric_template(output_dir, all_results, configuration_by_name)
    return 0


def _fmt(v: Optional[float]) -> str:
    return "" if v is None else f"{v:.3f}"


def _write_rubric_template(
    output_dir: str,
    all_results: Dict[str, List[Dict]],
    configuration_by_name: Dict[str, Dict[str, str]],
) -> None:
    rubric_path = os.path.join(output_dir, "manual_rubric.csv")
    fields = [
        "configuration",
        "configuration_label",
        "method_id",
        "number",
        "input_key",
        "label_truth",
        "classification_pred",
        "testable",
        "valid_artifact",
        "validated",
        "notes",
    ]
    with open(rubric_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for configuration, results in all_results.items():
            config = configuration_by_name[configuration]
            for r in results:
                writer.writerow(
                    {
                        "configuration": configuration,
                        "configuration_label": config["label"],
                        "method_id": config["method_id"],
                        "number": r["number"],
                        "input_key": r["input_key"],
                        "label_truth": r["label"],
                        "classification_pred": r["classification"],
                        "testable": "",
                        "valid_artifact": "",
                        "validated": "",
                        "notes": "",
                    }
                )


if __name__ == "__main__":
    raise SystemExit(main())
