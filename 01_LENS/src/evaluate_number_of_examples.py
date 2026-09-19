"""Figure 4: effect of the number of example pairs on prompt inference.

Vary n in {1..7}. For each n, draw 10 samples of (n attack seeds, n safe
seeds) -- without replacement when the design space allows -- and run the
full LENS pipeline end-to-end on each sample, then evaluate the resulting
(round-2 PoC prompt + induced context prompt + web_search at inference
time) on ``data/diameter/evaluation_dataset.csv``.

Outputs:

    <run_dir>/run_config.json                             input parameters
    <run_dir>/n<NN>/sample<MM>__a*_s*/<LENS artifacts>    per-sample results
    <run_dir>/n<NN>/n<NN>_summary.{csv,json}              per-n table
    <run_dir>/number_of_examples_summary.{csv,json}       flat union table
    <run_dir>/number_of_examples_run.json                 tokens + total time

Example::

    python -u -m src.evaluate_number_of_examples \\
        --service gpt5.4 --workers 10 --combo-workers 2

    python -u -m src.evaluate_number_of_examples \\
        --ns 1,2,3,4,5,6,7 --samples-per-n 10
"""
from __future__ import annotations

import argparse
import csv
import itertools
import os
import random
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import (
    EVAL_DIR,
    ensure_dir,
    read_json,
    timestamp,
    write_json,
)
from ._example_pair_support import (
    DEFAULT_ATTACK_NUMS,
    DEFAULT_SAFE_NUMS,
    DEFAULT_EVALUATION_DATASET,
    DEFAULT_SEED_EXAMPLES_FILE,
    _build_seed_pool,
    _evaluate_targets_with_lens,
    _seed_failure_reports,
)
from .evaluate_lens_effectiveness import _ensure_m6_round2_artifacts
from .llm import LLMRunner
from .samples import Sample, load_labeled_targets_file


SampleSpec = Tuple[Tuple[int, ...], Tuple[int, ...]]   # (attack_nums, safe_nums)


def _enumerate_sample_specs(
    n: int,
    attack_nums: List[int],
    safe_nums: List[int],
    samples_per_n: int,
    rng_seed: int,
) -> List[SampleSpec]:
    """Pick samples_per_n distinct (attacks, safes) combos for a given n.

    Sampling is without replacement when enough combinations are available.
    """
    rng = random.Random((rng_seed * 100003) ^ (n * 9176))
    if n < 1 or n > min(len(attack_nums), len(safe_nums)):
        return []

    attack_combos = list(itertools.combinations(sorted(attack_nums), n))
    safe_combos = list(itertools.combinations(sorted(safe_nums), n))
    full_space = [(a, s) for a in attack_combos for s in safe_combos]
    rng.shuffle(full_space)
    if len(full_space) >= samples_per_n:
        return full_space[:samples_per_n]
    out = list(full_space)
    while len(out) < samples_per_n and full_space:
        out.append(rng.choice(full_space))
    return out


def _sample_dir_name(idx: int, spec: SampleSpec) -> str:
    a_part = "-".join(f"{x:02d}" for x in spec[0])
    s_part = "-".join(f"{x:02d}" for x in spec[1])
    return f"sample{idx:02d}__a{a_part}__s{s_part}"


def _run_one_sample(
    n: int,
    sample_idx: int,
    spec: SampleSpec,
    attack_pool: Dict[int, Sample],
    safe_pool: Dict[int, Sample],
    targets: List[Sample],
    n_dir: str,
    runner: LLMRunner,
    workers: int,
    force: bool,
) -> Dict:
    sample_dir = ensure_dir(os.path.join(n_dir, _sample_dir_name(sample_idx, spec)))
    seeds = [attack_pool[a] for a in spec[0]] + [safe_pool[s] for s in spec[1]]
    write_json(os.path.join(sample_dir, "sample_meta.json"), {
        "n": n,
        "sample_idx": sample_idx,
        "attack_nums": list(spec[0]),
        "safe_nums": list(spec[1]),
        "attack_titles": [attack_pool[a].title for a in spec[0]],
        "safe_titles": [safe_pool[s].title for s in spec[1]],
        "attack_messages": [attack_pool[a].message_full for a in spec[0]],
        "safe_messages": [safe_pool[s].message_full for s in spec[1]],
    })

    a_str = ",".join(str(x) for x in spec[0])
    s_str = ",".join(str(x) for x in spec[1])
    print("\n" + "#" * 78)
    print(f"# n={n} sample {sample_idx:02d}  attacks=[{a_str}]  safes=[{s_str}]")
    print("#" * 78)

    started = time.time()
    seed_failure_dir = _seed_failure_reports(
        runner, seeds, sample_dir, workers, force,
    )
    ctx_prompt_text, round2_poc_prompt = _ensure_m6_round2_artifacts(
        runner=runner,
        variant="M7c",
        seeds=seeds,
        output_dir=sample_dir,
        seed_failure_dir=seed_failure_dir,
        force=force,
    )
    results = _evaluate_targets_with_lens(
        runner=runner,
        targets=targets,
        instruction=round2_poc_prompt,
        context_prompt=ctx_prompt_text,
        combo_dir=sample_dir,
        workers=workers,
        force=force,
    )
    elapsed = time.time() - started

    cm = read_json(os.path.join(sample_dir, "evaluation_dataset", "confusion_matrix.json"))
    metrics = cm.get("metrics", {})
    sample_summary = {
        "n": n,
        "sample_idx": sample_idx,
        "attack_nums": list(spec[0]),
        "safe_nums": list(spec[1]),
        "attack_messages": [attack_pool[a].message_full for a in spec[0]],
        "safe_messages": [safe_pool[s].message_full for s in spec[1]],
        "elapsed_seconds": elapsed,
        "metrics": metrics,
        "matrix": cm.get("matrix", {}),
        "n_targets": len(results),
        "output_dir": sample_dir,
        "source": "fresh",
    }
    write_json(os.path.join(sample_dir, "sample_summary.json"), sample_summary)
    return sample_summary


_FIELDS = [
    "n", "sample_idx", "attack_nums", "safe_nums",
    "accuracy", "attack_precision", "attack_recall", "safe_recall",
    "true_positive_attack", "false_negative_attack",
    "true_negative_safe", "false_positive_attack", "unknown_predictions",
    "elapsed_seconds", "source", "output_dir",
]


def _row_for(summary: Dict) -> Dict:
    metrics = summary.get("metrics") or {}
    return {
        "n": summary.get("n"),
        "sample_idx": summary.get("sample_idx"),
        "attack_nums": "-".join(str(x) for x in (summary.get("attack_nums") or [])),
        "safe_nums": "-".join(str(x) for x in (summary.get("safe_nums") or [])),
        "accuracy": metrics.get("accuracy"),
        "attack_precision": metrics.get("attack_precision"),
        "attack_recall": metrics.get("attack_recall"),
        "safe_recall": metrics.get("safe_recall"),
        "true_positive_attack": metrics.get("true_positive_attack"),
        "false_negative_attack": metrics.get("false_negative_attack"),
        "true_negative_safe": metrics.get("true_negative_safe"),
        "false_positive_attack": metrics.get("false_positive_attack"),
        "unknown_predictions": metrics.get("unknown_predictions"),
        "elapsed_seconds": summary.get("elapsed_seconds"),
        "source": summary.get("source", ""),
        "output_dir": summary.get("output_dir", ""),
    }


def _write_n_summary(n: int, rows: List[Dict], n_dir: str) -> None:
    csv_path = os.path.join(n_dir, f"n{n:02d}_summary.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS)
        writer.writeheader()
        for r in sorted(rows, key=lambda r: r.get("sample_idx", 0)):
            writer.writerow(_row_for(r))
    write_json(os.path.join(n_dir, f"n{n:02d}_summary.json"), rows)


def _write_top_summary(rows: List[Dict], output_root: str) -> None:
    rows = sorted(rows, key=lambda r: (r.get("n", 0), r.get("sample_idx", 0)))
    csv_path = os.path.join(output_root, "number_of_examples_summary.csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow(_row_for(r))
    write_json(os.path.join(output_root, "number_of_examples_summary.json"), rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Figure 4: LENS sensitivity to 1..7 example pairs.",
    )
    parser.add_argument("--evaluation-dataset", default=DEFAULT_EVALUATION_DATASET)
    parser.add_argument("--seed-examples", default=DEFAULT_SEED_EXAMPLES_FILE)
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--combo-workers", type=int, default=2)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--ns", default="1,2,3,4,5,6,7",
                        help="Comma-separated list of n values to evaluate.")
    parser.add_argument("--samples-per-n", type=int, default=10)
    parser.add_argument("--rng-seed", type=int, default=42)
    parser.add_argument("--attack-nums", default=",".join(str(x) for x in DEFAULT_ATTACK_NUMS))
    parser.add_argument("--safe-nums", default=",".join(str(x) for x in DEFAULT_SAFE_NUMS))
    parser.add_argument("--include-numbers", default=None)
    args = parser.parse_args()

    attack_pool, safe_pool = _build_seed_pool(args.seed_examples)
    attack_nums = [int(x) for x in args.attack_nums.split(",") if x.strip()]
    safe_nums = [int(x) for x in args.safe_nums.split(",") if x.strip()]
    ns = [int(x) for x in args.ns.split(",") if x.strip()]

    targets = load_labeled_targets_file(args.evaluation_dataset)
    if args.include_numbers:
        keep = {int(s) for s in args.include_numbers.split(",") if s.strip()}
        targets = [t for t in targets if t.number in keep]
    targets.sort(key=lambda s: s.number)
    if not targets:
        print("ERROR: no evaluation fields after filter.", file=sys.stderr)
        return 1

    output_root = args.output_dir or os.path.join(
        EVAL_DIR, "output", args.service, "number_of_examples", f"run_{timestamp()}",
    )
    ensure_dir(output_root)

    n_to_specs: Dict[int, List[SampleSpec]] = {}
    for n in ns:
        n_to_specs[n] = _enumerate_sample_specs(
            n, attack_nums, safe_nums, args.samples_per_n, args.rng_seed,
        )

    write_json(os.path.join(output_root, "run_config.json"), {
        "service": args.service,
        "seed_examples_file": args.seed_examples,
        "evaluation_dataset": args.evaluation_dataset,
        "n_targets": len(targets),
        "attack_pool": attack_nums,
        "safe_pool": safe_nums,
        "ns": ns,
        "samples_per_n": args.samples_per_n,
        "rng_seed": args.rng_seed,
        "selected_specs": {
            str(n): [{"attacks": list(a), "safes": list(s)} for (a, s) in specs]
            for n, specs in n_to_specs.items()
        },
        "workers": args.workers,
        "combo_workers": args.combo_workers,
    })

    print("=" * 78)
    print("Figure 4 example-count sensitivity (LENS)")
    print(f"  service       : {args.service}")
    print(f"  targets       : {len(targets)} from {args.evaluation_dataset}")
    print(f"  attack pool   : {attack_nums}")
    print(f"  safe pool     : {safe_nums}")
    for n in ns:
        print(f"  n={n}  -> {len(n_to_specs[n])} sample(s)")
    print(f"  output        : {output_root}")
    print("=" * 78)

    runner = LLMRunner(args.service)
    all_rows: List[Dict] = []
    rows_lock = threading.Lock()

    started = time.time()
    for n in ns:
        n_dir = ensure_dir(os.path.join(output_root, f"n{n:02d}"))
        n_specs = n_to_specs[n]
        n_rows: List[Dict] = []
        n_specs_indexed = list(enumerate(n_specs))

        def run_one(idx_spec: Tuple[int, SampleSpec]) -> Dict:
            idx, spec = idx_spec
            try:
                return _run_one_sample(
                    n, idx, spec, attack_pool, safe_pool, targets,
                    n_dir, runner, args.workers, args.force,
                )
            except Exception as exc:
                err = f"{type(exc).__name__}: {exc}"
                print(f"  [SAMPLE ERROR] n={n} idx={idx}: {err}")
                traceback.print_exc()
                return {
                    "n": n,
                    "sample_idx": idx,
                    "attack_nums": list(spec[0]),
                    "safe_nums": list(spec[1]),
                    "metrics": {},
                    "matrix": {},
                    "elapsed_seconds": 0.0,
                    "error": err,
                    "source": "error",
                    "output_dir": os.path.join(n_dir, _sample_dir_name(idx, spec)),
                }

        if args.combo_workers <= 1:
            for idx_spec in n_specs_indexed:
                summary = run_one(idx_spec)
                n_rows.append(summary)
                with rows_lock:
                    all_rows.append(summary)
                    _write_top_summary(all_rows, output_root)
                _write_n_summary(n, n_rows, n_dir)
        else:
            with ThreadPoolExecutor(max_workers=args.combo_workers) as pool:
                futures = [pool.submit(run_one, x) for x in n_specs_indexed]
                for fut in as_completed(futures):
                    summary = fut.result()
                    n_rows.append(summary)
                    with rows_lock:
                        all_rows.append(summary)
                        _write_top_summary(all_rows, output_root)
                    _write_n_summary(n, n_rows, n_dir)
        _write_n_summary(n, n_rows, n_dir)

    elapsed = time.time() - started
    _write_top_summary(all_rows, output_root)
    write_json(os.path.join(output_root, "number_of_examples_run.json"), {
        "elapsed_seconds": elapsed,
        "token_stats": runner.get_stats(),
        "n_samples": len(all_rows),
        "output_dir": output_root,
    })

    print("\n=== Example-count summary ===")
    by_n: Dict[int, List[Dict]] = {}
    for row in all_rows:
        by_n.setdefault(row.get("n"), []).append(row)
    for n in sorted(by_n):
        accs = [r.get("metrics", {}).get("accuracy") for r in by_n[n]
                if isinstance(r.get("metrics", {}).get("accuracy"), (int, float))]
        if accs:
            mean = sum(accs) / len(accs)
            lo, hi = min(accs), max(accs)
            print(f"  n={n}  count={len(by_n[n])}  acc mean={mean:.3f}  "
                  f"min={lo:.3f}  max={hi:.3f}")
        else:
            print(f"  n={n}  count={len(by_n[n])}  (no metrics)")
    print(f"  output: {output_root}")
    print(f"  total tokens: {runner.get_stats()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
