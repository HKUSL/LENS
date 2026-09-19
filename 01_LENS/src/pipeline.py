from __future__ import annotations

import hashlib
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional

from .common import ensure_dir, file_ready, read_text, write_text, write_display_report
from .llm import LLMRunner
from .parsing import parse_acceptability, parse_classification
from .prompts import (
    build_context_preparation_prompt,
    build_context_prompt_construction_prompt,
    build_exploit_assessment_prompt,
    build_poc_prompt_construction_prompt,
    build_replay_validation_prompt,
)
from .samples import Sample, SupportSet, build_input_for_case
from .specs import SpecCache


DEFAULT_MAX_PROMPT_CHARS = 180000


@dataclass
class PipelineOptions:
    service_name: str
    max_workers: int = 7
    info_rounds: int = 3
    force: bool = False
    max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS


def run_support_set_pipeline(
    support: SupportSet,
    output_dir: str,
    options: PipelineOptions,
) -> Dict:
    ensure_dir(output_dir)
    runner = LLMRunner(options.service_name)

    summary = {
        "support_id": support.support_id,
        "sample_count": support.sample_count,
        "max_refinement_rounds": options.info_rounds,
        "converged": False,
        "converged_round": None,
        "status": "running",
        "rounds": {},
    }

    current_input_dir = None
    current_instruction = None
    current_context_prompt = None
    validation_results = None
    failed_records = None

    for round_index in range(0, options.info_rounds + 1):
        round_dir = ensure_dir(os.path.join(output_dir, f"round_{round_index:02d}"))
        round_summary: Dict = {"round_index": round_index}

        if round_index > 0:
            if not failed_records:
                round_summary["context_prompt_construction"] = {"status": "skipped_no_failures"}
                round_summary["context_preparation"] = {"status": "skipped_no_failures"}
                summary["rounds"][round_index] = round_summary
                summary["converged"] = True
                summary["converged_round"] = round_index - 1
                break

            context_dir = os.path.join(round_dir, "context_prompt_construction")
            context_prompt, context_meta = context_prompt_construction(
                failed_records=failed_records,
                support_samples=support.samples,
                instruction=current_instruction,
                output_dir=context_dir,
                runner=runner,
                info_round=round_index,
                input_override_dir=current_input_dir,
                record_mode="full",
                max_prompt_chars=options.max_prompt_chars,
                force=options.force,
            )
            round_summary["context_prompt_construction"] = context_meta
            if not context_prompt:
                summary["rounds"][round_index] = round_summary
                summary["status"] = "failed"
                return summary
            current_context_prompt = context_prompt

            prep_dir = os.path.join(round_dir, "context_preparation")
            prep_results = context_preparation(
                samples=support.samples,
                context_prompt=context_prompt,
                output_dir=prep_dir,
                runner=runner,
                previous_input_dir=current_input_dir,
                use_specs=False,
                specs_dir=None,
                max_workers=options.max_workers,
                force=options.force,
            )
            round_summary["context_preparation"] = _count_status(prep_results, prep_dir)
            current_input_dir = prep_dir

        poc_dir = os.path.join(round_dir, "poc_prompt_construction")
        current_instruction, poc_meta = poc_prompt_construction(
            samples=support.samples,
            output_dir=poc_dir,
            runner=runner,
            input_override_dir=current_input_dir,
            record_mode="full",
            max_prompt_chars=options.max_prompt_chars,
            force=options.force,
        )
        round_summary["poc_prompt_construction"] = poc_meta
        if not current_instruction:
            summary["rounds"][round_index] = round_summary
            summary["status"] = "failed"
            return summary

        assessment_dir = os.path.join(round_dir, "exploit_assessment")
        assessment_results = exploit_assessment(
            samples=support.samples,
            instruction=current_instruction,
            output_dir=assessment_dir,
            runner=runner,
            input_override_dir=current_input_dir,
            max_workers=options.max_workers,
            force=options.force,
        )
        round_summary["exploit_assessment"] = _count_status(assessment_results, assessment_dir)
        validation_dir = os.path.join(round_dir, "replay_validation")
        validation_results, failed_records = replay_validation(
            samples=support.samples,
            assessment_results=assessment_results,
            output_dir=validation_dir,
            runner=runner,
            max_workers=options.max_workers,
            force=options.force,
        )
        round_summary["replay_validation"] = {
            **_count_status(validation_results, validation_dir),
            "acceptable": sum(1 for r in validation_results if r.get("acceptable") is True),
            "needs_refinement": sum(1 for r in validation_results if r.get("acceptable") is False),
            "unknown": sum(1 for r in validation_results if r.get("acceptable") is None),
            "failures_for_context": len(failed_records),
        }

        summary["rounds"][round_index] = round_summary
        if not failed_records:
            summary["converged"] = True
            summary["converged_round"] = round_index
            break

    _write_final_prompt_files(summary, output_dir, current_instruction, current_context_prompt)

    summary["status"] = "completed"
    return summary


def _write_final_prompt_files(
    summary: Dict,
    output_dir: str,
    instruction: Optional[str],
    context_prompt: Optional[str],
) -> None:
    rounds = summary.get("rounds") or {}
    summary["final_round"] = max((int(k) for k in rounds.keys()), default=None)

    final_files = {}
    if instruction:
        write_text(os.path.join(output_dir, "final_instruction.txt"), instruction)
        final_files["instruction"] = "final_instruction.txt"
    if context_prompt:
        write_text(os.path.join(output_dir, "final_context_prompt.txt"), context_prompt)
        final_files["context_prompt"] = "final_context_prompt.txt"
    summary["final_prompt_files"] = final_files


def poc_prompt_construction(
    samples: List[Sample],
    output_dir: str,
    runner: LLMRunner,
    input_override_dir: str = None,
    record_mode: str = "full",
    max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS,
    force: bool = False,
) -> tuple[Optional[str], Dict]:
    ensure_dir(output_dir)
    instruction_path = os.path.join(output_dir, "final_instruction.txt")
    if not force and file_ready(instruction_path):
        return read_text(instruction_path), {"status": "skipped", "output_dir": output_dir}

    prompt = build_poc_prompt_construction_prompt(
        samples,
        input_override_dir=input_override_dir,
        record_mode=record_mode,
    )
    full_prompt_chars = len(prompt)
    prompt_mode = record_mode
    compacted = False
    if _prompt_exceeds_budget(prompt, max_prompt_chars) and record_mode != "minimal":
        prompt = build_poc_prompt_construction_prompt(
            samples,
            input_override_dir=input_override_dir,
            record_mode="minimal",
        )
        prompt_mode = "minimal_auto"
        compacted = True
    write_text(os.path.join(output_dir, "poc_prompt_construction_input.txt"), prompt)
    instruction = runner.generate(prompt, retry_on_refusal=True)
    if not instruction and record_mode != "minimal" and not compacted:
        retry_prompt = build_poc_prompt_construction_prompt(
            samples,
            input_override_dir=input_override_dir,
            record_mode="minimal",
        )
        if retry_prompt != prompt:
            write_text(os.path.join(output_dir, "poc_prompt_construction_input_minimal_retry.txt"), retry_prompt)
            instruction = runner.generate(retry_prompt, retry_on_refusal=True)
            prompt = retry_prompt
            prompt_mode = "minimal_retry"
            compacted = True
    if not instruction:
        return (
            None,
            {
                "status": "error",
                "output_dir": output_dir,
                "prompt_chars": len(prompt),
                "full_prompt_chars": full_prompt_chars,
                "prompt_mode": prompt_mode,
                "compacted": compacted,
            },
        )

    write_text(instruction_path, instruction)
    return (
        instruction,
        {
            "status": "success",
            "instruction_length": len(instruction),
            "output_dir": output_dir,
            "prompt_chars": len(prompt),
            "full_prompt_chars": full_prompt_chars,
            "prompt_mode": prompt_mode,
            "compacted": compacted,
        },
    )


def exploit_assessment(
    samples: List[Sample],
    instruction: str,
    output_dir: str,
    runner: LLMRunner,
    input_override_dir: str = None,
    max_workers: int = 7,
    force: bool = False,
    parse_reports: bool = True,
    save_summary: bool = True,
) -> List[Dict]:
    ensure_dir(output_dir)
    write_text(os.path.join(output_dir, "instruction_used.txt"), instruction)
    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        stem = _output_stem(sample)
        response_path = os.path.join(output_dir, f"{stem}_response.txt")
        prompt_path = os.path.join(output_dir, f"{stem}_prompt.txt")

        if not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            status = "skipped"
        else:
            sample_input = build_input_for_case(sample, input_override_dir=input_override_dir)
            prompt = build_exploit_assessment_prompt(sample_input, instruction)
            write_text(prompt_path, prompt)
            response = runner.generate(prompt)
            status = "success" if response else "error"
            if response:
                if parse_reports:
                    write_text(response_path, response)
                else:
                    write_display_report(response_path, response)

        result = {
            "number": sample.number,
            "title": sample.title,
            "label": sample.label,
            "message_full": sample.message_full,
            "message_abbr": sample.message_abbr,
            "target_path": sample.target_path,
            "input_key": sample.input_key,
            "response": response or "",
            "response_file": os.path.basename(response_path),
            "status": status,
        }
        if parse_reports:
            result["classification"] = parse_classification(response or "")
        with lock:
            completed[0] += 1
            print(f"  [{completed[0]}/{len(samples)}] assess {sample.input_key} - {status}")
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(process, sample): sample for sample in samples}
        for future in as_completed(futures):
            sample = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                response_path = os.path.join(output_dir, f"{_output_stem(sample)}_response.txt")
                with lock:
                    completed[0] += 1
                    print(f"  [{completed[0]}/{len(samples)}] final {sample.input_key} - exception ({exc})")
                results.append(
                    _final_batch_result(
                        sample,
                        context_status="error",
                        assessment_status="error",
                        response_path=response_path,
                        spec_name=None,
                        error=str(exc),
                        classification="UNKNOWN" if parse_reports else None,
                    )
                )

    results.sort(key=lambda r: r["number"])
    return results


def replay_validation(
    samples: List[Sample],
    assessment_results: List[Dict],
    output_dir: str,
    runner: LLMRunner,
    max_workers: int = 7,
    force: bool = False,
) -> tuple[List[Dict], List[Dict]]:
    ensure_dir(output_dir)
    sample_by_key = {s.input_key: s for s in samples}
    result_by_key = {r["input_key"]: r for r in assessment_results}
    validation_results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        assessment = result_by_key.get(sample.input_key, {})
        generated = assessment.get("response", "")
        generated_classification = assessment.get("classification", "UNKNOWN")
        stem = _output_stem(sample)
        response_path = os.path.join(output_dir, f"{stem}_validation.txt")
        prompt_path = os.path.join(output_dir, f"{stem}_validation_prompt.txt")

        if sample.label == "SAFE" and generated_classification == "SAFE":
            validation_response = (
                "Replay validation skipped: the generated report and the ground-truth sample are both SAFE.\n\n"
                "Conclusion: ACCEPTABLE"
            )
            write_text(response_path, validation_response)
            status = "skipped_safe_match"
        elif not force and file_ready(response_path, min_size=30):
            validation_response = read_text(response_path)
            status = "skipped"
        elif not generated:
            validation_response = ""
            status = "error"
        else:
            prompt = build_replay_validation_prompt(sample, generated)
            write_text(prompt_path, prompt)
            validation_response = runner.generate(prompt)
            status = "success" if validation_response else "error"
            if validation_response:
                write_text(response_path, validation_response)

        acceptable = parse_acceptability(validation_response or "")
        result = {
            "number": sample.number,
            "input_key": sample.input_key,
            "label": sample.label,
            "target_path": sample.target_path,
            "generated_classification": generated_classification,
            "acceptable": acceptable,
            "validation_response": validation_response or "",
            "validation_file": os.path.basename(response_path),
            "status": status,
        }
        with lock:
            completed[0] += 1
            if status == "error":
                print(f"  Seed validation failed: {sample.input_key}")
        return result

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            validation_results.append(future.result())

    validation_results.sort(key=lambda r: r["number"])
    failed_records = []
    for result in validation_results:
        if result.get("acceptable") is True:
            continue
        sample = sample_by_key[result["input_key"]]
        assessment = result_by_key.get(sample.input_key, {})
        failed_records.append(
            {
                "sample": sample,
                "assessment_result": assessment,
                "generated_report": assessment.get("response", ""),
                "validation_response": result.get("validation_response", ""),
                "acceptable": result.get("acceptable"),
            }
        )

    return validation_results, failed_records


def context_prompt_construction(
    failed_records: List[Dict],
    support_samples: List[Sample],
    instruction: str,
    output_dir: str,
    runner: LLMRunner,
    info_round: int,
    input_override_dir: str = None,
    record_mode: str = "full",
    max_prompt_chars: int = DEFAULT_MAX_PROMPT_CHARS,
    force: bool = False,
) -> tuple[Optional[str], Dict]:
    ensure_dir(output_dir)
    final_path = os.path.join(output_dir, "final_context_prompt.txt")
    if not force and file_ready(final_path):
        return read_text(final_path), {"status": "skipped", "failure_count": len(failed_records), "output_dir": output_dir}

    prompt = build_context_prompt_construction_prompt(
        failed_records=failed_records,
        support_samples=support_samples,
        instruction=instruction,
        info_round=info_round,
        input_override_dir=input_override_dir,
        record_mode=record_mode,
    )
    full_prompt_chars = len(prompt)
    prompt_mode = record_mode
    compacted = False
    if _prompt_exceeds_budget(prompt, max_prompt_chars) and record_mode != "minimal":
        prompt = build_context_prompt_construction_prompt(
            failed_records=failed_records,
            support_samples=support_samples,
            instruction=instruction,
            info_round=info_round,
            input_override_dir=input_override_dir,
            record_mode="minimal",
        )
        prompt_mode = "minimal_auto"
        compacted = True
    write_text(os.path.join(output_dir, "context_prompt_construction_input.txt"), prompt)
    context_prompt = runner.generate(prompt)
    if not context_prompt and record_mode != "minimal" and not compacted:
        retry_prompt = build_context_prompt_construction_prompt(
            failed_records=failed_records,
            support_samples=support_samples,
            instruction=instruction,
            info_round=info_round,
            input_override_dir=input_override_dir,
            record_mode="minimal",
        )
        if retry_prompt != prompt:
            write_text(os.path.join(output_dir, "context_prompt_construction_input_minimal_retry.txt"), retry_prompt)
            context_prompt = runner.generate(retry_prompt)
            prompt = retry_prompt
            prompt_mode = "minimal_retry"
            compacted = True
    if not context_prompt:
        return (
            None,
            {
                "status": "error",
                "failure_count": len(failed_records),
                "output_dir": output_dir,
                "prompt_chars": len(prompt),
                "full_prompt_chars": full_prompt_chars,
                "prompt_mode": prompt_mode,
                "compacted": compacted,
            },
        )

    write_text(final_path, context_prompt)
    return (
        context_prompt,
        {
            "status": "success",
            "failure_count": len(failed_records),
            "context_prompt_length": len(context_prompt),
            "output_dir": output_dir,
            "prompt_chars": len(prompt),
            "full_prompt_chars": full_prompt_chars,
            "prompt_mode": prompt_mode,
            "compacted": compacted,
        },
    )


def context_preparation(
    samples: List[Sample],
    context_prompt: str,
    output_dir: str,
    runner: LLMRunner,
    previous_input_dir: str = None,
    use_specs: bool = False,
    specs_dir: str = None,
    max_workers: int = 7,
    force: bool = False,
) -> List[Dict]:
    ensure_dir(output_dir)
    write_text(os.path.join(output_dir, "context_prompt_used.txt"), context_prompt)
    spec_cache = SpecCache(specs_dir) if use_specs else None
    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        input_path = os.path.join(output_dir, f"{sample.input_key}_input.txt")
        prompt_path = os.path.join(output_dir, f"{sample.input_key}_context_prompt.txt")

        if not force and file_ready(input_path, min_size=30):
            enriched = read_text(input_path)
            status = "skipped"
            spec_name = None
        else:
            spec_name = None
            spec_text = None
            if use_specs:
                spec_entry = spec_cache.get_for_interface(sample.interface)
                if not spec_entry:
                    with lock:
                        completed[0] += 1
                        print(f"  [{completed[0]}/{len(samples)}] context {sample.input_key} - error (no spec)")
                    return {
                        "number": sample.number,
                        "input_key": sample.input_key,
                        "status": "error",
                        "error": f"no spec for interface {sample.interface}",
                    }
                spec_name, spec_text = spec_entry

            sample_input = build_input_for_case(sample, input_override_dir=previous_input_dir)
            prompt = build_context_preparation_prompt(context_prompt, sample_input, spec_name, spec_text)
            write_text(prompt_path, prompt)
            enriched = _generate_meaningful_context(runner, prompt, sample_input)
            status = "success" if enriched else "error"
            if enriched:
                write_text(input_path, enriched)

        with lock:
            completed[0] += 1
            print(f"  [{completed[0]}/{len(samples)}] context {sample.input_key} - {status}")
        return {
            "number": sample.number,
            "input_key": sample.input_key,
            "label": sample.label,
            "target_path": sample.target_path,
            "status": status,
            "input_file": os.path.basename(input_path),
            "spec_document": spec_name,
            "chars": len(enriched or ""),
        }

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r["number"])
    return results


def final_batch_analysis(
    samples: List[Sample],
    instruction: str,
    context_prompt: str,
    output_dir: str,
    runner: LLMRunner,
    use_specs: bool = False,
    specs_dir: str = None,
    max_workers: int = 10,
    force: bool = False,
) -> List[Dict]:
    """Run context preparation and exploit assessment for many final targets.

    The two LLM calls for one target stay in the same worker so completed
    contexts can immediately flow into assessment without a global phase barrier.
    Existing context and response files are reused unless ``force`` is set.
    """
    ensure_dir(output_dir)
    context_dir = ensure_dir(os.path.join(output_dir, "context_preparation"))
    assessment_dir = ensure_dir(os.path.join(output_dir, "exploit_assessment"))
    write_text(os.path.join(output_dir, "instruction_used.txt"), instruction)
    write_text(os.path.join(output_dir, "context_prompt_used.txt"), context_prompt)

    spec_cache = SpecCache(specs_dir) if use_specs else None
    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        stem = _output_stem(sample)
        context_path = os.path.join(context_dir, f"{stem}_input.txt")
        context_prompt_path = os.path.join(context_dir, f"{stem}_context_prompt.txt")
        response_path = os.path.join(assessment_dir, f"{stem}_response.txt")
        assessment_prompt_path = os.path.join(assessment_dir, f"{stem}_prompt.txt")

        context_status = "pending"
        assessment_status = "pending"
        spec_name = None

        base_input = build_input_for_case(sample)
        if not force and file_ready(context_path, min_size=30):
            enriched_context = read_text(context_path)
            context_status = "skipped"
        else:
            spec_text = None
            if use_specs:
                spec_entry = spec_cache.get_for_interface(sample.interface)
                if not spec_entry:
                    return _final_batch_result(
                        sample,
                        context_status="error",
                        assessment_status="skipped",
                        response_path=response_path,
                        spec_name=None,
                        error=f"no spec for interface {sample.interface}",
                    )
                spec_name, spec_text = spec_entry

            prompt = build_context_preparation_prompt(context_prompt, base_input, spec_name, spec_text)
            write_text(context_prompt_path, prompt)
            enriched_context = _generate_meaningful_context(runner, prompt, base_input)
            context_status = "success" if enriched_context else "error"
            if enriched_context:
                write_text(context_path, enriched_context)

        if context_status == "error":
            response = ""
            assessment_status = "skipped"
        elif not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            assessment_status = "skipped"
        else:
            full_input = f"{base_input.rstrip()}\n\n===Protocol Evidence===\n{enriched_context.strip()}\n"
            assessment_prompt = build_exploit_assessment_prompt(full_input, instruction)
            write_text(assessment_prompt_path, assessment_prompt)
            response = runner.generate(assessment_prompt)
            assessment_status = "success" if response else "error"

        if response:
            write_display_report(response_path, response)
        with lock:
            completed[0] += 1
            print(
                f"  [{completed[0]}/{len(samples)}] final {sample.input_key} - "
                f"context:{context_status} assess:{assessment_status}"
            )

        return _final_batch_result(
            sample,
            context_status=context_status,
            assessment_status=assessment_status,
            response_path=response_path,
            spec_name=spec_name,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: (r.get("message_full", ""), r.get("target_path", "")))
    return results


def _prompt_exceeds_budget(prompt: str, max_prompt_chars: Optional[int]) -> bool:
    return bool(max_prompt_chars and max_prompt_chars > 0 and len(prompt) > max_prompt_chars)


def _count_status(results: List[Dict], output_dir: str) -> Dict:
    def _status(row: Dict) -> str:
        if row.get("status"):
            return row["status"]
        if row.get("assessment_status"):
            return row["assessment_status"]
        return ""

    return {
        "status": "success" if results else "empty",
        "total": len(results),
        "success": sum(1 for r in results if _status(r) == "success"),
        "skipped": sum(1 for r in results if _status(r) == "skipped"),
        "errors": sum(1 for r in results if _status(r) == "error"),
        "output_dir": output_dir,
    }


def _output_stem(sample: Sample) -> str:
    safe_path = sample.target_path.replace(".", "_").replace("-", "_").replace(" ", "_")
    key_match = re.match(r"^(case|eval|val)\d+", sample.input_key or "")
    short_key = key_match.group(0) if key_match else f"sample{sample.number}"
    stem = f"{short_key}_{sample.message_abbr}_{safe_path}"
    if len(stem) <= 36:
        return stem
    digest = hashlib.sha1(stem.encode("utf-8")).hexdigest()[:10]
    prefix = f"{short_key}_{sample.message_abbr}"
    remaining = max(8, 36 - len(prefix) - len(digest) - 2)
    return f"{prefix}_{safe_path[:remaining].rstrip('_')}_{digest}"


def _generate_meaningful_context(runner: LLMRunner, prompt: str, original_input: str) -> Optional[str]:
    for _ in range(3):
        generated = runner.generate(prompt)
        if generated and not _is_trivially_unenriched(generated, original_input):
            return generated
    return None


def _is_trivially_unenriched(generated_input: str, original_input: str) -> bool:
    generated = "\n".join(line.rstrip() for line in generated_input.strip().splitlines()).strip()
    original = "\n".join(line.rstrip() for line in original_input.strip().splitlines()).strip()
    if not generated:
        return True
    if generated == original:
        return True
    if len(generated.splitlines()) <= len(original.splitlines()) + 1 and original in generated:
        return True
    return False


def _final_batch_result(
    sample: Sample,
    context_status: str,
    assessment_status: str,
    response_path: str,
    spec_name: str = None,
    error: str = None,
    classification: Optional[str] = None,
) -> Dict:
    status = (
        "success"
        if context_status in {"success", "skipped"} and assessment_status in {"success", "skipped"}
        else "error"
    )
    result = {
        "number": sample.number,
        "title": sample.title,
        "label": sample.label,
        "message_full": sample.message_full,
        "message_abbr": sample.message_abbr,
        "target_path": sample.target_path,
        "interface": sample.interface,
        "input_key": sample.input_key,
        "source": sample.source,
        "context_status": context_status,
        "assessment_status": assessment_status,
        "response_file": os.path.basename(response_path),
        "spec_document": spec_name,
        "status": status,
    }
    if classification is not None:
        result["classification"] = classification
    if error:
        result["error"] = error
    return result
