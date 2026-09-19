"""Protocol generalizability experiment for prompt and context induction.

Default flow:
  round_00: induce Prompt_poc from seed ATTACK/SAFE examples, then replay seeds.
  round_01: induce Prompt_ctx from round_00 seed reports + Prompt_poc, then collect seed context via web_search.
  round_02: re-induce Prompt_poc from enriched seed inputs.

Optional later rounds alternate context-prompt refinement and PoC-prompt re-induction.
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Sequence, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import EVAL_DIR, ensure_dir, file_ready, read_json, read_text, timestamp, write_json, write_text
from .llm import LLMRunner
from .generalizability_prompts import (
    build_context_preparation_prompt,
    build_context_prompt_from_enriched_failures,
    build_context_prompt_induction_with_poc,
    build_exploit_assessment_prompt,
    build_poc_prompt_construction_prompt,
    build_websearch_nudge,
)
from .parsing import parse_classification
from .samples import (
    Sample,
    build_input_for_case,
    load_labeled_targets_file,
    load_target_paths_file,
    parse_index_list,
    parse_seed_examples,
)


def execute_experiment(
    seed_examples_file: str,
    service: str = "gpt5.4",
    attack_indices: Optional[Sequence[int]] = None,
    safe_indices: Optional[Sequence[int]] = None,
    selected_case: Optional[int] = None,
    attack_side: str = "request",
    rounds: int = 3,
    workers: int = 7,
    record_mode: str = "full",
    output_dir: Optional[str] = None,
    targets_file: Optional[str] = None,
    target_paths_file: Optional[str] = None,
    target_side: str = "all",
    include_numbers: Optional[Sequence[int]] = None,
    protocol: Optional[str] = None,
    target_type: Optional[str] = None,
    force: bool = False,
) -> Dict:
    if rounds < 3:
        raise ValueError("--rounds must be at least 3 for the generalizability workflow")

    attacks = parse_seed_examples(seed_examples_file, label="ATTACK", attack_side=attack_side)
    safes = parse_seed_examples(seed_examples_file, label="SAFE")
    supports = _select_seed_pairs(attacks, safes, attack_indices, safe_indices, selected_case)
    if not supports:
        raise ValueError("No seed pairs selected. Check --seeds/--attack-indices and SAFE selection.")

    targets = _load_targets(
        targets_file=targets_file,
        target_paths_file=target_paths_file,
        target_side=target_side,
        include_numbers=include_numbers,
        protocol=protocol,
        target_type=target_type,
    )
    if not targets:
        raise ValueError(
            "No target fields loaded. Check --target-paths-file/--targets-file "
            "and the protocol parser."
        )

    output_root = output_dir or os.path.join(
        EVAL_DIR,
        "output",
        service,
        "generalizability",
        timestamp(),
    )
    ensure_dir(output_root)

    config = {
        "seed_examples_file": os.path.abspath(seed_examples_file),
        "service": service,
        "attack_indices": list(attack_indices or []),
        "safe_indices": list(safe_indices or []),
        "selected_case": selected_case,
        "attack_side": attack_side,
        "rounds": rounds,
        "workers": workers,
        "record_mode": record_mode,
        "targets_file": targets_file,
        "target_paths_file": target_paths_file,
        "target_side": target_side,
        "include_numbers": list(include_numbers or []),
        "protocol": protocol,
        "target_type": target_type,
        "supports": [_support_manifest(support_id, seeds) for support_id, seeds in supports],
    }
    write_json(os.path.join(output_root, "experiment_config.json"), config)

    print("=" * 80)
    print("Generalizability Experiment")
    print(f"  Seed examples: {seed_examples_file}")
    print(f"  Service: {service}")
    print(f"  Seed pairs: {len(supports)}")
    print(f"  Rounds: {rounds}")
    print(f"  Targets: {len(targets)}")
    print(f"  Output: {output_root}")
    print("=" * 80)

    summaries: Dict[str, Dict] = {}
    for support_id, seeds in supports:
        support_dir = ensure_dir(os.path.join(output_root, support_id))
        runner = LLMRunner(service)
        try:
            summary = execute_support(
                support_id=support_id,
                seeds=seeds,
                targets=targets,
                output_dir=support_dir,
                runner=runner,
                rounds=rounds,
                workers=workers,
                record_mode=record_mode,
                force=force,
            )
        except Exception as exc:
            summary = {
                "support_id": support_id,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }
            write_json(os.path.join(support_dir, "summary.json"), summary)
            print(f"  [SUPPORT ERROR] {support_id}: {summary['error']}")
        summaries[support_id] = summary
        write_json(os.path.join(output_root, "experiment_summary.json"), summaries)

    write_json(os.path.join(output_root, "experiment_summary.json"), summaries)
    print_final_summary(summaries)
    return summaries


def execute_support(
    support_id: str,
    seeds: List[Sample],
    targets: List[Sample],
    output_dir: str,
    runner: LLMRunner,
    rounds: int,
    workers: int,
    record_mode: str,
    force: bool,
) -> Dict:
    ensure_dir(output_dir)
    write_json(os.path.join(output_dir, "seed_manifest.json"), _support_manifest(support_id, seeds))

    summary: Dict = {
        "support_id": support_id,
        "status": "running",
        "rounds_requested": rounds,
        "rounds": {},
    }

    current_instruction = _induce_poc_prompt(
        samples=seeds,
        output_dir=ensure_dir(os.path.join(output_dir, "round_00", "poc_prompt_construction")),
        runner=runner,
        input_override_dir=None,
        record_mode=record_mode,
        force=force,
    )
    seed_results = _assess_samples(
        samples=seeds,
        instruction=current_instruction,
        output_dir=ensure_dir(os.path.join(output_dir, "round_00", "exploit_assessment")),
        runner=runner,
        workers=workers,
        force=force,
    )
    failed_records = _records_from_seed_results(seeds, seed_results)
    summary["rounds"]["round_00"] = {
        "poc_prompt": "round_00/poc_prompt_construction/final_instruction.txt",
        "seed_reports": len(seed_results),
        "failed_records_for_context_induction": len(failed_records),
    }

    current_context_prompt = _induce_context_prompt(
        failed_records=failed_records,
        instruction=current_instruction,
        output_dir=ensure_dir(os.path.join(output_dir, "round_01", "context_prompt_construction")),
        runner=runner,
        record_mode=record_mode,
        force=force,
    )
    seed_context_dir = _collect_contexts(
        samples=seeds,
        context_prompt=current_context_prompt,
        output_dir=ensure_dir(os.path.join(output_dir, "round_01", "seed_context")),
        runner=runner,
        workers=workers,
        force=force,
    )
    summary["rounds"]["round_01"] = {
        "context_prompt": "round_01/context_prompt_construction/final_context_prompt.txt",
        "seed_context_dir": "round_01/seed_context",
    }

    current_instruction = _induce_poc_prompt(
        samples=seeds,
        output_dir=ensure_dir(os.path.join(output_dir, "round_02", "poc_prompt_construction")),
        runner=runner,
        input_override_dir=seed_context_dir,
        record_mode=record_mode,
        force=force,
    )
    seed_results = _assess_samples(
        samples=seeds,
        instruction=current_instruction,
        output_dir=ensure_dir(os.path.join(output_dir, "round_02", "exploit_assessment")),
        runner=runner,
        input_override_dir=seed_context_dir,
        workers=workers,
        force=force,
    )
    failed_records = _attach_collected_context(
        _records_from_seed_results(seeds, seed_results),
        seed_context_dir,
    )
    summary["rounds"]["round_02"] = {
        "poc_prompt": "round_02/poc_prompt_construction/final_instruction.txt",
        "seed_reports": len(seed_results),
    }

    last_context_dir = seed_context_dir
    for round_index in range(3, rounds):
        round_name = f"round_{round_index:02d}"
        round_dir = ensure_dir(os.path.join(output_dir, round_name))
        if round_index % 2 == 1:
            current_context_prompt = _refine_context_prompt(
                failed_records=failed_records,
                instruction=current_instruction,
                previous_context_prompt=current_context_prompt,
                output_dir=ensure_dir(os.path.join(round_dir, "context_prompt_construction")),
                runner=runner,
                record_mode=record_mode,
                force=force,
            )
            last_context_dir = _collect_contexts(
                samples=seeds,
                context_prompt=current_context_prompt,
                output_dir=ensure_dir(os.path.join(round_dir, "seed_context")),
                runner=runner,
                workers=workers,
                force=force,
            )
            summary["rounds"][round_name] = {
                "stage": "context_refinement",
                "context_prompt": f"{round_name}/context_prompt_construction/final_context_prompt.txt",
                "seed_context_dir": f"{round_name}/seed_context",
            }
        else:
            current_instruction = _induce_poc_prompt(
                samples=seeds,
                output_dir=ensure_dir(os.path.join(round_dir, "poc_prompt_construction")),
                runner=runner,
                input_override_dir=last_context_dir,
                record_mode=record_mode,
                force=force,
            )
            seed_results = _assess_samples(
                samples=seeds,
                instruction=current_instruction,
                output_dir=ensure_dir(os.path.join(round_dir, "exploit_assessment")),
                runner=runner,
                input_override_dir=last_context_dir,
                workers=workers,
                force=force,
            )
            failed_records = _attach_collected_context(
                _records_from_seed_results(seeds, seed_results),
                last_context_dir,
            )
            summary["rounds"][round_name] = {
                "stage": "poc_reinduction",
                "poc_prompt": f"{round_name}/poc_prompt_construction/final_instruction.txt",
                "seed_reports": len(seed_results),
            }

    write_text(os.path.join(output_dir, "final_instruction.txt"), current_instruction)
    write_text(os.path.join(output_dir, "final_context_prompt.txt"), current_context_prompt)

    if targets:
        target_results = _assess_targets(
            samples=targets,
            instruction=current_instruction,
            context_prompt=current_context_prompt,
            output_dir=ensure_dir(os.path.join(output_dir, "target_assessment")),
            runner=runner,
            workers=workers,
            force=force,
        )
        summary["target_assessment"] = {
            "total": len(target_results),
            "status_counts": _count_status(target_results),
            "classification_counts": _count_classifications(target_results),
            "confusion_matrix": _save_confusion_matrix(
                os.path.join(output_dir, "target_assessment"),
                target_results,
            ),
        }

    summary["status"] = "completed"
    summary["token_stats"] = runner.get_stats()
    write_json(os.path.join(output_dir, "summary.json"), summary)
    return summary


def _induce_poc_prompt(
    samples: List[Sample],
    output_dir: str,
    runner: LLMRunner,
    input_override_dir: Optional[str],
    record_mode: str,
    force: bool,
) -> str:
    final_path = os.path.join(output_dir, "final_instruction.txt")
    if not force and file_ready(final_path):
        return read_text(final_path)
    prompt = build_poc_prompt_construction_prompt(samples, input_override_dir, record_mode)
    write_text(os.path.join(output_dir, "poc_prompt_construction_input.txt"), prompt)
    instruction = runner.generate(prompt, retry_on_refusal=True)
    if not instruction:
        raise RuntimeError(f"failed to induce PoC prompt in {output_dir}")
    write_text(final_path, instruction)
    write_json(
        os.path.join(output_dir, "metadata.json"),
        {
            "status": "success",
            "sample_count": len(samples),
            "input_override_dir": input_override_dir,
            "record_mode": record_mode,
            "prompt_chars": len(prompt),
            "instruction_length": len(instruction),
        },
    )
    return instruction


def _induce_context_prompt(
    failed_records: List[Dict],
    instruction: str,
    output_dir: str,
    runner: LLMRunner,
    record_mode: str,
    force: bool,
) -> str:
    final_path = os.path.join(output_dir, "final_context_prompt.txt")
    if not force and file_ready(final_path):
        return read_text(final_path)
    prompt = build_context_prompt_induction_with_poc(failed_records, instruction, record_mode=record_mode)
    write_text(os.path.join(output_dir, "context_prompt_construction_input.txt"), prompt)
    context_prompt = runner.generate(prompt)
    if not context_prompt:
        raise RuntimeError(f"failed to induce context prompt in {output_dir}")
    write_text(final_path, context_prompt)
    return context_prompt


def _refine_context_prompt(
    failed_records: List[Dict],
    instruction: str,
    previous_context_prompt: str,
    output_dir: str,
    runner: LLMRunner,
    record_mode: str,
    force: bool,
) -> str:
    final_path = os.path.join(output_dir, "final_context_prompt.txt")
    if not force and file_ready(final_path):
        return read_text(final_path)
    prompt = build_context_prompt_from_enriched_failures(
        failed_records=failed_records,
        instruction=instruction,
        previous_context_prompt=previous_context_prompt,
        include_previous_context_prompt=True,
        record_mode=record_mode,
    )
    write_text(os.path.join(output_dir, "context_prompt_construction_input.txt"), prompt)
    context_prompt = runner.generate(prompt)
    if not context_prompt:
        raise RuntimeError(f"failed to refine context prompt in {output_dir}")
    write_text(final_path, context_prompt)
    return context_prompt


def _collect_contexts(
    samples: List[Sample],
    context_prompt: str,
    output_dir: str,
    runner: LLMRunner,
    workers: int,
    force: bool,
) -> str:
    ensure_dir(output_dir)
    write_text(os.path.join(output_dir, "context_prompt_used.txt"), context_prompt)
    results: List[Dict] = []
    lock = threading.Lock()

    def process(sample: Sample) -> Dict:
        path = os.path.join(output_dir, f"{sample.input_key}_input.txt")
        search_log = os.path.join(output_dir, f"{sample.input_key}_searches.json")
        if not force and file_ready(path, min_size=30):
            status = "skipped"
            text = read_text(path)
        else:
            target_input = build_input_for_case(sample)
            prompt = build_context_preparation_prompt(context_prompt, target_input)
            write_text(os.path.join(output_dir, f"{sample.input_key}_context_prompt.txt"), prompt)
            result = runner.generate_with_websearch(prompt, nudge=build_websearch_nudge(sample))
            text = (result or {}).get("text", "")
            status = "success" if text else "error"
            if text:
                write_text(path, text)
            write_json(
                search_log,
                {
                    "search_calls": (result or {}).get("search_calls", []),
                    "usage": (result or {}).get("usage", {}),
                    "elapsed_s": (result or {}).get("elapsed_s"),
                },
            )
        row = {
            "number": sample.number,
            "input_key": sample.input_key,
            "label": sample.label,
            "target_path": sample.target_path,
            "status": status,
            "input_file": os.path.basename(path),
            "chars": len(text or ""),
        }
        with lock:
            results.append(row)
            print(f"  [{len(results)}/{len(samples)}] context {sample.input_key} - {status}")
        return row

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(samples)))) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            future.result()
    results.sort(key=lambda row: row["number"])
    _write_rows(output_dir, "context_summary", results)
    return output_dir


def _assess_samples(
    samples: List[Sample],
    instruction: str,
    output_dir: str,
    runner: LLMRunner,
    workers: int,
    force: bool,
    input_override_dir: Optional[str] = None,
) -> List[Dict]:
    ensure_dir(output_dir)
    write_text(os.path.join(output_dir, "instruction_used.txt"), instruction)
    results: List[Dict] = []
    lock = threading.Lock()

    def process(sample: Sample) -> Dict:
        prompt_path = os.path.join(output_dir, f"{sample.input_key}_prompt.txt")
        response_path = os.path.join(output_dir, f"{sample.input_key}_response.txt")
        if not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            status = "skipped"
        else:
            sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
            prompt = build_exploit_assessment_prompt(sample_input, instruction)
            write_text(prompt_path, prompt)
            response = runner.generate(prompt) or ""
            status = "success" if response else "error"
            if response:
                write_text(response_path, response)
        classification = parse_classification(response)
        row = _result_row(sample, classification, status, response_path, response)
        with lock:
            results.append(row)
            print(f"  [{len(results)}/{len(samples)}] assess {sample.input_key} {sample.label}->{classification} ({status})")
        return row

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(samples)))) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            future.result()
    results.sort(key=lambda row: row["number"])
    _write_rows(output_dir, "assessment_summary", results)
    return results


def _assess_targets(
    samples: List[Sample],
    instruction: str,
    context_prompt: str,
    output_dir: str,
    runner: LLMRunner,
    workers: int,
    force: bool,
) -> List[Dict]:
    ensure_dir(output_dir)
    write_text(os.path.join(output_dir, "instruction_used.txt"), instruction)
    write_text(os.path.join(output_dir, "context_prompt_used.txt"), context_prompt)
    ctx_dir = ensure_dir(os.path.join(output_dir, "_target_ctx"))
    results: List[Dict] = []
    lock = threading.Lock()

    def process(sample: Sample) -> Dict:
        ctx_path = os.path.join(ctx_dir, f"{sample.input_key}.txt")
        search_log = os.path.join(ctx_dir, f"{sample.input_key}_searches.json")
        target_input = build_input_for_case(sample)
        if not force and file_ready(ctx_path, min_size=30):
            ctx_text = read_text(ctx_path)
            context_status = "skipped"
        else:
            ctx_prompt = build_context_preparation_prompt(context_prompt, target_input)
            write_text(os.path.join(ctx_dir, f"{sample.input_key}_context_prompt.txt"), ctx_prompt)
            result = runner.generate_with_websearch(ctx_prompt, nudge=build_websearch_nudge(sample))
            ctx_text = (result or {}).get("text", "")
            context_status = "success" if ctx_text else "error"
            if ctx_text:
                write_text(ctx_path, ctx_text)
            write_json(
                search_log,
                {
                    "search_calls": (result or {}).get("search_calls", []),
                    "usage": (result or {}).get("usage", {}),
                    "elapsed_s": (result or {}).get("elapsed_s"),
                },
            )

        response_path = os.path.join(output_dir, f"{sample.input_key}_response.txt")
        prompt_path = os.path.join(output_dir, f"{sample.input_key}_prompt.txt")
        if context_status == "error":
            response = ""
            status = "ctx_error"
        elif not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            status = "skipped"
        else:
            full_input = f"{target_input.rstrip()}\n\n===Protocol Evidence===\n{ctx_text.strip()}\n"
            prompt = build_exploit_assessment_prompt(full_input, instruction)
            write_text(prompt_path, prompt)
            response = runner.generate(prompt) or ""
            status = "success" if response else "error"
            if response:
                write_text(response_path, response)
        classification = parse_classification(response)
        row = _result_row(sample, classification, status, response_path, response)
        row["context_status"] = context_status
        with lock:
            results.append(row)
            print(f"  [{len(results)}/{len(samples)}] target {sample.input_key} {sample.label}->{classification} ({status})")
        return row

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(samples)))) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            future.result()
    results.sort(key=lambda row: row["number"])
    _write_rows(output_dir, "results", results)
    return results


def _records_from_seed_results(seeds: List[Sample], results: List[Dict]) -> List[Dict]:
    by_key = {row["input_key"]: row for row in results}
    records = []
    for sample in seeds:
        row = by_key.get(sample.input_key, {})
        records.append(
            {
                "sample": sample,
                "generated_report": row.get("response", ""),
                "assessment_result": {k: v for k, v in row.items() if k != "response"},
                "acceptable": False,
            }
        )
    return records


def _attach_collected_context(failed_records: List[Dict], context_dir: Optional[str]) -> List[Dict]:
    if not context_dir:
        return failed_records
    out = []
    for record in failed_records:
        sample = record["sample"]
        path = os.path.join(context_dir, f"{sample.input_key}_input.txt")
        out.append({**record, "collected_context": read_text(path) if os.path.exists(path) else ""})
    return out


def _select_seed_pairs(
    attacks: List[Sample],
    safes: List[Sample],
    attack_indices: Optional[Sequence[int]],
    safe_indices: Optional[Sequence[int]],
    selected_case: Optional[int],
) -> List[Tuple[str, List[Sample]]]:
    attack_by_num = {s.number: s for s in attacks}
    safe_by_num = {s.number: s for s in safes}
    attack_nums = list(attack_indices or [s.number for s in attacks])
    safe_nums = list(safe_indices or [])
    supports = []
    for pos, attack_num in enumerate(attack_nums):
        attack = attack_by_num.get(attack_num)
        if not attack:
            continue
        safe_num = selected_case
        if safe_num is None and safe_nums:
            safe_num = safe_nums[pos] if pos < len(safe_nums) else safe_nums[-1]
        if safe_num is None:
            safe_num = attack_num + 10 if attack_num + 10 in safe_by_num else (safes[0].number if safes else None)
        safe = safe_by_num.get(safe_num) if safe_num is not None else None
        if not safe:
            continue
        support_id = (
            f"seed_pair_attack_{attack.number:02d}_safe_{safe.number:02d}"
        )
        supports.append((support_id, [attack, safe]))
    return supports


def _load_targets(
    targets_file: Optional[str],
    target_paths_file: Optional[str],
    target_side: str,
    include_numbers: Optional[Sequence[int]],
    protocol: Optional[str],
    target_type: Optional[str],
) -> List[Sample]:
    targets: List[Sample] = []
    if targets_file:
        targets.extend(load_labeled_targets_file(targets_file, message_side=target_side))
    if target_paths_file:
        targets.extend(
            load_target_paths_file(
                target_paths_file,
                message_side=target_side,
                protocol=protocol,
                target_type=target_type,
            )
        )
    if include_numbers:
        keep = set(include_numbers)
        targets = [sample for sample in targets if sample.number in keep]
    return targets


def _result_row(sample: Sample, classification: str, status: str, response_path: str, response: str) -> Dict:
    return {
        "number": sample.number,
        "title": sample.title,
        "label": sample.label,
        "interface": sample.interface,
        "message_full": sample.message_full,
        "message_abbr": sample.message_abbr,
        "target_type": sample.target_type,
        "target_path": sample.target_path,
        "input_key": sample.input_key,
        "classification": classification,
        "status": status,
        "response_file": os.path.basename(response_path),
        "response": response,
    }


def _support_manifest(support_id: str, seeds: List[Sample]) -> Dict:
    return {
        "support_id": support_id,
        "seeds": [sample.to_dict() for sample in seeds],
    }


def _count_status(rows: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for row in rows:
        status = row.get("status", "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _count_classifications(rows: List[Dict]) -> Dict[str, int]:
    counts = {"ATTACK": 0, "SAFE": 0, "UNKNOWN": 0, "OTHER": 0}
    for row in rows:
        classification = row.get("classification") or "UNKNOWN"
        key = classification if classification in counts else "OTHER"
        counts[key] += 1
    return counts


def _write_rows(output_dir: str, name: str, rows: List[Dict]) -> None:
    write_json(os.path.join(output_dir, f"{name}.json"), [{k: v for k, v in row.items() if k != "response"} for row in rows])
    if not rows:
        return
    keys = [key for key in rows[0].keys() if key != "response"]
    with open(os.path.join(output_dir, f"{name}.csv"), "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in keys})


def _save_confusion_matrix(output_dir: str, results: List[Dict]) -> Dict:
    labels = ["ATTACK", "SAFE"]
    pred_labels = ["ATTACK", "SAFE", "UNKNOWN", "OTHER"]
    matrix = {label: {pred: 0 for pred in pred_labels} for label in labels}
    for row in results:
        actual = row.get("label")
        if actual not in labels:
            continue
        pred = row.get("classification", "UNKNOWN")
        if pred not in pred_labels:
            pred = "OTHER"
        matrix[actual][pred] += 1
    tp = matrix["ATTACK"]["ATTACK"]
    fn = matrix["ATTACK"]["SAFE"] + matrix["ATTACK"]["UNKNOWN"] + matrix["ATTACK"]["OTHER"]
    fp = matrix["SAFE"]["ATTACK"]
    tn = matrix["SAFE"]["SAFE"]
    total_attack = tp + fn
    total_safe = sum(matrix["SAFE"].values())
    total = total_attack + total_safe
    payload = {
        "matrix": matrix,
        "metrics": {
            "accuracy": (tp + tn) / total if total else None,
            "attack_precision": tp / (tp + fp) if (tp + fp) else None,
            "attack_recall": tp / total_attack if total_attack else None,
            "safe_recall": tn / total_safe if total_safe else None,
            "true_positive_attack": tp,
            "false_negative_attack": fn,
            "true_negative_safe": tn,
            "false_positive_attack": fp,
            "unknown_predictions": matrix["ATTACK"]["UNKNOWN"] + matrix["SAFE"]["UNKNOWN"],
        },
    }
    write_json(os.path.join(output_dir, "confusion_matrix.json"), payload)
    return payload


def print_final_summary(summaries: Dict[str, Dict]) -> None:
    print("\n" + "=" * 80)
    print("Generalizability Experiment Summary")
    print("=" * 80)
    for support_id, summary in summaries.items():
        target = summary.get("target_assessment", {})
        print(f"  {support_id:16s} | {summary.get('status')} | targets={target.get('total', 0)}")
    print("=" * 80)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute one component of the non-Diameter generalizability experiment."
    )
    parser.add_argument("--seed-examples", required=True)
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument("--seeds", default=None, help="Alias for --attack-indices.")
    parser.add_argument("--attack-indices", default=None, help="Comma-separated ATTACK sample numbers.")
    parser.add_argument("--safe-indices", default=None, help="Comma-separated SAFE sample numbers.")
    parser.add_argument("--selected-case", type=int, default=None, help="SAFE sample number reused for every selected ATTACK seed.")
    parser.add_argument("--attack-side", default="request", choices=["request", "answer", "all"])
    parser.add_argument("--rounds", type=int, default=3, help="Stages to execute. Default 3: baseline PoC, context, enriched PoC.")
    parser.add_argument("--workers", type=int, default=7)
    parser.add_argument("--record-mode", choices=["full", "minimal"], default="full")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--targets-file", default=None, help="Labeled target CSV.")
    parser.add_argument("--target-paths-file", default=None, help="Unlabeled target path file or CSV.")
    parser.add_argument("--target-side", default="all", choices=["request", "answer", "all"])
    parser.add_argument("--include-numbers", default=None, help="Comma-separated target number values to keep.")
    parser.add_argument("--protocol", default=None, help="Optional protocol/interface override for target path files, e.g. sip, oci, n1, s6a.")
    parser.add_argument("--target-type", default=None, help="Optional target type override, e.g. AVP, IE, Header, Setting.")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    attack_raw = args.attack_indices or args.seeds
    summaries = execute_experiment(
        seed_examples_file=args.seed_examples,
        service=args.service,
        attack_indices=parse_index_list(attack_raw),
        safe_indices=parse_index_list(args.safe_indices),
        selected_case=args.selected_case,
        attack_side=args.attack_side,
        rounds=args.rounds,
        workers=args.workers,
        record_mode=args.record_mode,
        output_dir=args.output_dir,
        targets_file=args.targets_file,
        target_paths_file=args.target_paths_file,
        target_side=args.target_side,
        include_numbers=parse_index_list(args.include_numbers),
        protocol=args.protocol,
        target_type=args.target_type,
        force=args.force,
    )
    return 0 if all(
        summary.get("status") == "completed"
        for summary in summaries.values()
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
