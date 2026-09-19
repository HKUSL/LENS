"""Run the Simple Prompt baseline on a field-path list.

This is the large-scale counterpart of the paper's Simple Prompt configuration. Unlike
``evaluate_protocol_level_findings.py``, it does not use a fixed induced instruction/context pair;
each target is prompted with ``build_zero_shot_prompt(target_input)`` directly.
"""
from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .baselines import build_zero_shot_prompt
from .common import EVAL_DIR, ensure_dir, file_ready, read_text, timestamp, write_text, write_display_report
from .llm import LLMRunner
from .pipeline import _output_stem
from .samples import Sample, build_input_for_case, load_avp_paths_file


DEFAULT_FIELD_PATHS = os.path.join(
    EVAL_DIR, "data", "diameter", "s6a_field_paths.txt"
)


def run_simple_prompt(
    samples: List[Sample],
    output_dir: str,
    runner: LLMRunner,
    workers: int,
    force: bool,
) -> List[Dict]:
    ensure_dir(output_dir)
    results: List[Dict] = []
    lock = threading.Lock()
    completed = [0]

    def process(sample: Sample) -> Dict:
        stem = _output_stem(sample)
        prompt_path = os.path.join(output_dir, f"{stem}_prompt.txt")
        response_path = os.path.join(output_dir, f"{stem}_response.txt")
        if not force and file_ready(response_path, min_size=30):
            response = read_text(response_path)
            status = "skipped"
        else:
            target_input = build_input_for_case(sample)
            prompt = build_zero_shot_prompt(target_input)
            write_text(prompt_path, prompt)
            response = runner.generate(prompt)
            status = "success" if response else "error"

        if response:
            write_display_report(response_path, response)
        result = {
            "number": sample.number,
            "title": sample.title,
            "message_full": sample.message_full,
            "message_abbr": sample.message_abbr,
            "target_path": sample.target_path,
            "interface": sample.interface,
            "input_key": sample.input_key,
            "source": sample.source,
            "status": status,
            "response_file": os.path.basename(response_path),
            "response": response or "",
        }
        with lock:
            completed[0] += 1
            print(
                f"  [{completed[0]}/{len(samples)}] Simple Prompt {sample.input_key} "
                f"- {status}"
            )
        return result

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(process, sample) for sample in samples]
        for future in as_completed(futures):
            results.append(future.result())

    results.sort(key=lambda r: r["number"])
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the Simple Prompt baseline over a field-path list."
    )
    parser.add_argument("--field-paths", default=DEFAULT_FIELD_PATHS)
    parser.add_argument("--message-side", default="request",
                        choices=["request", "answer", "all"])
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    samples = load_avp_paths_file(args.field_paths, message_side=args.message_side)
    if not samples:
        raise ValueError("No targets loaded. Check --field-paths and --message-side.")

    target_name = os.path.splitext(os.path.basename(args.field_paths))[0]
    output_dir = args.output_dir or os.path.join(
        EVAL_DIR,
        "output",
        args.service,
        "simple_prompt_field_paths",
        f"{target_name}_{args.message_side}_{timestamp()}",
    )
    ensure_dir(output_dir)

    print("=" * 80)
    print("Simple Prompt field-path analysis")
    print(f"  targets: {len(samples)}")
    print(f"  field paths: {args.field_paths}")
    print(f"  message side: {args.message_side}")
    print(f"  service: {args.service}")
    print(f"  workers: {args.workers}")
    print(f"  output: {output_dir}")
    print("=" * 80)

    runner = LLMRunner(args.service)
    started = time.time()
    results = run_simple_prompt(samples, output_dir, runner, args.workers, args.force)
    elapsed = time.time() - started

    print("\n=== Simple Prompt summary ===")
    print(f"  total: {len(results)}")
    print(f"  elapsed: {elapsed:.1f}s")
    print(f"  output: {output_dir}")
    print(f"  total tokens: {runner.get_stats()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
