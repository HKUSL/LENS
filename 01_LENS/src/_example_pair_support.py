"""Shared LENS helpers for the number-of-examples experiment."""
from __future__ import annotations

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import (
    EVAL_DIR,
    ensure_dir,
    file_ready,
    read_text,
    write_json,
    write_text,
)
from .evaluate_lens_effectiveness import (
    WEBSEARCH_NUDGE,
    _prepare_induced_context_websearch,
    _wrap_with_context,
)
from .llm import LLMRunner
from .parsing import parse_classification
from .pipeline import (
    _save_confusion_matrix,
    exploit_assessment,
    poc_prompt_construction,
)
from .prompts import build_exploit_assessment_prompt
from .samples import (
    Sample,
    build_input_for_case,
    parse_seed_examples,
)


DEFAULT_EVALUATION_DATASET = os.path.join(
    EVAL_DIR, "data", "diameter", "evaluation_dataset.csv"
)
DEFAULT_SEED_EXAMPLES_FILE = os.path.join(
    EVAL_DIR, "data", "diameter", "seed_examples.md"
)
DEFAULT_ATTACK_NUMS = list(range(1, 9))      # 1..8 (Request-side attacks)
DEFAULT_SAFE_NUMS = list(range(11, 19))      # 11..18 (Request-side safes)


def _build_seed_pool(seed_examples_file: str) -> Tuple[Dict[int, Sample], Dict[int, Sample]]:
    attacks = parse_seed_examples(seed_examples_file, label="ATTACK", attack_side="all")
    safes = parse_seed_examples(seed_examples_file, label="SAFE")
    return ({s.number: s for s in attacks}, {s.number: s for s in safes})


def _seed_failure_reports(
    runner: LLMRunner,
    seeds: List[Sample],
    combo_dir: str,
    workers: int,
    force: bool,
) -> str:
    """Generate round_00 PoC prompt + per-seed exploit_assessment responses.

    Returns the round_00 directory (matches the layout that
    `_ensure_m6_round2_artifacts` expects via `--seed-failure-dir`).
    """
    round0_dir = ensure_dir(os.path.join(combo_dir, "round_00"))
    poc_dir = ensure_dir(os.path.join(round0_dir, "poc_prompt_construction"))
    instruction_path = os.path.join(poc_dir, "final_instruction.txt")
    if force or not file_ready(instruction_path):
        instruction, _ = poc_prompt_construction(
            samples=seeds,
            output_dir=poc_dir,
            runner=runner,
            input_override_dir=None,
            record_mode="full",
            force=force,
        )
        if not instruction:
            raise RuntimeError(f"failed round_00 PoC induction in {poc_dir}")
    else:
        instruction = read_text(instruction_path)

    assess_dir = ensure_dir(os.path.join(round0_dir, "exploit_assessment"))
    exploit_assessment(
        samples=seeds,
        instruction=instruction,
        output_dir=assess_dir,
        runner=runner,
        max_workers=min(workers, len(seeds)),
        force=force,
    )
    return round0_dir


def _evaluate_targets_with_lens(
    runner: LLMRunner,
    targets: List[Sample],
    instruction: str,
    context_prompt: str,
    combo_dir: str,
    workers: int,
    force: bool,
) -> List[Dict]:
    eval_dir = ensure_dir(os.path.join(combo_dir, "evaluation_dataset"))
    write_text(os.path.join(eval_dir, "instruction_used.txt"), instruction)
    write_text(os.path.join(eval_dir, "context_prompt_used.txt"), context_prompt)
    ctx_dir = ensure_dir(os.path.join(eval_dir, "_target_ctx"))

    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        key = sample.input_key
        target_input = build_input_for_case(sample)

        ctx_cache = os.path.join(ctx_dir, f"{key}.txt")
        search_log = os.path.join(ctx_dir, f"{key}_searches.json")
        ctx_text = _prepare_induced_context_websearch(
            runner, context_prompt, target_input, ctx_cache, force, search_log,
        )
        if not ctx_text:
            with lock:
                completed[0] += 1
                print(f"  [{completed[0]}/{len(targets)}] {key} CTX FAIL")
            return {
                "input_key": key, "number": sample.number, "label": sample.label,
                "interface": sample.interface, "message_full": sample.message_full,
                "target_path": sample.target_path,
                "classification": "UNKNOWN", "status": "ctx_error",
            }

        prompt_path = os.path.join(eval_dir, f"{key}_prompt.txt")
        response_path = os.path.join(eval_dir, f"{key}_response.txt")
        if not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            status = "skipped"
        else:
            full_input = _wrap_with_context(target_input, ctx_text)
            exploit_prompt = build_exploit_assessment_prompt(full_input, instruction)
            write_text(prompt_path, exploit_prompt)
            response = runner.generate(exploit_prompt)
            status = "success" if response else "error"
            if response:
                write_text(response_path, response)

        classification = parse_classification(response or "")
        with lock:
            completed[0] += 1
            print(f"  [{completed[0]}/{len(targets)}] {key} "
                  f"{sample.label}->{classification} ({status})")
        return {
            "input_key": key,
            "number": sample.number,
            "label": sample.label,
            "interface": sample.interface,
            "message_full": sample.message_full,
            "target_path": sample.target_path,
            "classification": classification,
            "status": status,
            "response_file": os.path.basename(response_path),
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(process, t) for t in targets]
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r["number"])
    write_json(os.path.join(eval_dir, "results.json"), results)
    _save_confusion_matrix(eval_dir, results)
    return results
