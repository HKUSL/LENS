from __future__ import annotations

import argparse
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import DEFAULT_SEED_EXAMPLES_FILE, EVAL_DIR, ensure_dir, write_json
from .pipeline import PipelineOptions, run_support_set_pipeline
from .samples import (
    SupportSet,
    parse_index_list,
    parse_seed_examples,
    select_support_sets,
)


def run_experiment(
    seed_examples_file: str = DEFAULT_SEED_EXAMPLES_FILE,
    services: Optional[List[str]] = None,
    sample_counts: Optional[List[int]] = None,
    attack_side: str = "request",
    attack_indices: Optional[List[int]] = None,
    safe_indices: Optional[List[int]] = None,
    max_support_sets: int = 1,
    safe_mode: str = "matched",
    output_dir: Optional[str] = None,
    info_rounds: int = 3,
    max_workers: int = 7,
    force: bool = False,
    max_prompt_chars: int = 180000,
    support_workers: int = 1,
) -> Dict:
    services = services or ["gpt5.4"]
    sample_counts = sample_counts or [1]
    if output_dir:
        base_output_dir = output_dir
    elif len(services) == 1:
        base_output_dir = os.path.join(EVAL_DIR, "output", services[0], "prompt_construction")
    else:
        base_output_dir = os.path.join(EVAL_DIR, "output", "prompt_construction_multi")
    ensure_dir(base_output_dir)

    attacks = parse_seed_examples(seed_examples_file, label="ATTACK", attack_side=attack_side)
    safes = parse_seed_examples(seed_examples_file, label="SAFE")
    support_sets = select_support_sets(
        attacks=attacks,
        safes=safes,
        sample_counts=sample_counts,
        attack_indices=attack_indices,
        safe_indices=safe_indices,
        max_sets_per_count=max_support_sets,
        safe_mode=safe_mode,
    )
    if not support_sets:
        raise ValueError("No support sets selected. Check sample counts and indices.")

    config = {
        "seed_examples_file": os.path.abspath(seed_examples_file),
        "services": services,
        "sample_counts": sample_counts,
        "attack_side": attack_side,
        "attack_indices": attack_indices,
        "safe_indices": safe_indices,
        "safe_mode": safe_mode,
        "max_support_sets": max_support_sets,
        "max_refinement_rounds": info_rounds,
        "support_sets": [s.to_dict() for s in support_sets],
        "max_prompt_chars": max_prompt_chars,
        "support_workers": support_workers,
    }
    write_json(os.path.join(base_output_dir, "experiment_config.json"), config)

    print("=" * 80)
    print("Multi-Sample Evaluation Pipeline")
    print(f"  Seed examples: {seed_examples_file}")
    print(f"  Services: {services}")
    print(f"  Sample counts: {sample_counts}")
    print(f"  Attack side: {attack_side}")
    print(f"  Support sets: {len(support_sets)}")
    print(f"  Max refinement rounds: {info_rounds}")
    print(f"  Max prompt chars: {max_prompt_chars}")
    print(f"  Support workers: {support_workers}")
    print(f"  Output: {base_output_dir}")
    print("=" * 80)

    summaries = {}
    single_service_default = not output_dir and len(services) == 1
    for service in services:
        if single_service_default:
            service_dir = ensure_dir(base_output_dir)
        else:
            service_dir = ensure_dir(os.path.join(base_output_dir, service))
        options = PipelineOptions(
            service_name=service,
            max_workers=max_workers,
            info_rounds=info_rounds,
            force=force,
            max_prompt_chars=max_prompt_chars,
        )
        summaries[service] = {}

        def run_one_support(support: SupportSet) -> tuple[str, Dict]:
            print("\n" + "#" * 80)
            print(f"# Service={service} | Support={support.support_id}")
            print("#" * 80)
            count_dir = ensure_dir(os.path.join(service_dir, f"m{support.sample_count:02d}"))
            support_dir = os.path.join(count_dir, support.support_id)
            try:
                summary = run_support_set_pipeline(
                    support=support,
                    output_dir=support_dir,
                    options=options,
                )
            except Exception as exc:
                summary = {
                    "support_id": support.support_id,
                    "sample_count": support.sample_count,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                }
                ensure_dir(support_dir)
                write_json(os.path.join(support_dir, "summary.json"), summary)
                print(f"  [SUPPORT ERROR] {support.support_id}: {summary['error']}")
            return support.support_id, summary

        if support_workers <= 1:
            for support in support_sets:
                support_id, summary = run_one_support(support)
                summaries[service][support_id] = summary
                write_json(os.path.join(base_output_dir, "experiment_summary.json"), summaries)
        else:
            with ThreadPoolExecutor(max_workers=support_workers) as pool:
                futures = [pool.submit(run_one_support, support) for support in support_sets]
                for future in as_completed(futures):
                    support_id, summary = future.result()
                    summaries[service][support_id] = summary
                    write_json(os.path.join(base_output_dir, "experiment_summary.json"), summaries)

    write_json(os.path.join(base_output_dir, "experiment_summary.json"), summaries)
    print_final_summary(summaries)
    return summaries


def print_final_summary(summaries: Dict) -> None:
    print("\n" + "=" * 80)
    print("Experiment Summary")
    print("=" * 80)
    for service, service_summary in summaries.items():
        for support_id, summary in service_summary.items():
            print(f"  {service:12s} | {support_id:35s} | {summary.get('status')}")
    print("=" * 80)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run multi-sample prompt-construction evaluation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.experiment --services gpt5.4 --sample-counts 1,2,4

  python -m src.experiment \\
    --services gpt5.4,claude \\
    --sample-counts 1,2,4 \\
    --max-support-sets 3 \\
    --attack-side request

  python -m src.experiment \\
    --services gpt5.4 \\
    --attack-indices 1,2,3,4 \\
    --safe-indices 11,12,13,14 \\
    --sample-counts 4
        """,
    )
    parser.add_argument("--seed-examples", default=DEFAULT_SEED_EXAMPLES_FILE)
    parser.add_argument("--service", default="gpt5.4", help="Single service name. Ignored when --services is set.")
    parser.add_argument("--services", default=None, help="Comma-separated service names.")
    parser.add_argument("--sample-counts", default="1", help="Comma-separated m values; m means m ATTACK + m SAFE.")
    parser.add_argument("--attack-side", default="request", choices=["request", "answer", "all"])
    parser.add_argument("--attack-indices", default=None, help="Comma-separated explicit ATTACK sample numbers.")
    parser.add_argument("--safe-indices", default=None, help="Comma-separated explicit SAFE sample numbers.")
    parser.add_argument("--max-support-sets", type=int, default=1)
    parser.add_argument("--safe-mode", default="matched", choices=["matched", "first"])
    parser.add_argument("--output-dir", default=None)
    parser.add_argument(
        "--info-rounds",
        type=int,
        default=3,
        help="Maximum context-refinement rounds after round 0 (default: 3). The run stops early when replay validation is acceptable for all support samples.",
    )
    parser.add_argument("--workers", type=int, default=7)
    parser.add_argument("--force", action="store_true", help="Ignore cached artifacts.")
    parser.add_argument(
        "--max-prompt-chars",
        type=int,
        default=180000,
        help="Prompt length budget in characters before automatic minimal fallback; use 0 to disable.",
    )
    parser.add_argument(
        "--support-workers",
        type=int,
        default=1,
        help="Number of support sets to run concurrently. Total LLM concurrency is roughly support-workers * workers.",
    )
    args = parser.parse_args()

    services = [s.strip() for s in args.services.split(",") if s.strip()] if args.services else [args.service]
    sample_counts = [int(s.strip()) for s in args.sample_counts.split(",") if s.strip()]

    run_experiment(
        seed_examples_file=args.seed_examples,
        services=services,
        sample_counts=sample_counts,
        attack_side=args.attack_side,
        attack_indices=parse_index_list(args.attack_indices),
        safe_indices=parse_index_list(args.safe_indices),
        max_support_sets=args.max_support_sets,
        safe_mode=args.safe_mode,
        output_dir=args.output_dir,
        info_rounds=args.info_rounds,
        max_workers=args.workers,
        force=args.force,
        max_prompt_chars=args.max_prompt_chars,
        support_workers=args.support_workers,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
