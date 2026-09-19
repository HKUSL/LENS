from __future__ import annotations

import argparse
import os
import re
import sys

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import DEFAULT_SPECS_DIR, EVAL_DIR, ensure_dir, read_json, read_text
from .llm import LLMRunner
from .pipeline import final_batch_analysis
from .samples import load_avp_paths_file, load_labeled_targets_file


def safe_path_component(value: str) -> str:
    value = value.strip()
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    cleaned = cleaned.strip("._-")
    return cleaned or "prompt"


def infer_prompt_id(instruction_path: str, context_prompt_path: str, prompt_dir: str = None) -> str:
    if prompt_dir:
        support_id = os.path.basename(os.path.normpath(prompt_dir))
        summary_path = os.path.join(prompt_dir, "summary.json")
        round_id = None
        if os.path.exists(summary_path):
            summary = read_json(summary_path)
            final_round = summary.get("final_round")
            if isinstance(final_round, int):
                round_id = f"round{final_round:02d}"
        if re.match(r"m\d{2}_", support_id):
            return safe_path_component(f"{support_id}_{round_id}" if round_id else support_id)

    paths = [context_prompt_path, instruction_path]
    for path in paths:
        parts = os.path.normpath(path).split(os.sep)
        support_id = next((part for part in parts if re.match(r"m\d{2}_", part)), None)
        round_id = next((part for part in reversed(parts) if re.match(r"round_\d{2}$", part)), None)
        if support_id and round_id:
            return safe_path_component(f"{support_id}_{round_id}")
        if support_id:
            return safe_path_component(support_id)

    stem = os.path.splitext(os.path.basename(context_prompt_path))[0]
    return safe_path_component(stem)


def resolve_prompt_paths(prompt_dir: str = None, instruction_path: str = None, context_prompt_path: str = None) -> tuple[str, str]:
    if not prompt_dir:
        if not instruction_path or not context_prompt_path:
            raise ValueError("Provide either --prompt-dir or both --instruction and --context-prompt.")
        return instruction_path, context_prompt_path

    instruction_path = os.path.join(prompt_dir, "final_instruction.txt")
    context_prompt_path = os.path.join(prompt_dir, "final_context_prompt.txt")
    if os.path.exists(instruction_path) and os.path.exists(context_prompt_path):
        return instruction_path, context_prompt_path

    round_dirs = [
        os.path.join(prompt_dir, name)
        for name in os.listdir(prompt_dir)
        if re.match(r"round_\d{2}$", name) and os.path.isdir(os.path.join(prompt_dir, name))
    ]
    round_dirs.sort(reverse=True)

    instruction_path = next(
        (
            os.path.join(path, "poc_prompt_construction", "final_instruction.txt")
            for path in round_dirs
            if os.path.exists(os.path.join(path, "poc_prompt_construction", "final_instruction.txt"))
        ),
        None,
    )
    context_prompt_path = next(
        (
            os.path.join(path, "context_prompt_construction", "final_context_prompt.txt")
            for path in round_dirs
            if os.path.exists(os.path.join(path, "context_prompt_construction", "final_context_prompt.txt"))
        ),
        None,
    )
    if not instruction_path or not context_prompt_path:
        raise ValueError(f"No final prompt pair found under {prompt_dir}. Check whether the run reached context prompt construction.")
    return instruction_path, context_prompt_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run final batch analysis from fixed PoC and context prompts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.batch_analysis \\
    --prompt-dir output/prompt_construction/gpt5.4/m01/m01_a04_s14 \\
    --targets-file data/diameter/evaluation_dataset.csv \\
    --service gpt5.4 \\
    --workers 20
        """,
    )
    parser.add_argument("--prompt-dir", default=None, help="Support-set output directory containing final prompt files.")
    parser.add_argument("--instruction", default=None, help="Path to final_instruction.txt")
    parser.add_argument("--context-prompt", default=None, help="Path to final_context_prompt.txt")
    parser.add_argument("--field-paths", default=None, help="Path to an unlabeled field-path list")
    parser.add_argument("--targets-file", default=None, help="Path to a labeled evaluation-dataset CSV")
    parser.add_argument("--message-side", default="all", choices=["request", "answer", "all"])
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument(
        "--prompt-id",
        default=None,
        help="Stable name for this fixed prompt pair in large-scale outputs. If omitted, inferred from the prompt paths.",
    )
    parser.add_argument("--workers", type=int, default=10, help="Concurrent target workers")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--use-specs", action="store_true")
    parser.add_argument("--specs-dir", default=DEFAULT_SPECS_DIR)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    instruction_path, context_prompt_path = resolve_prompt_paths(args.prompt_dir, args.instruction, args.context_prompt)
    instruction = read_text(instruction_path)
    context_prompt = read_text(context_prompt_path)
    if args.targets_file:
        targets = load_labeled_targets_file(args.targets_file, message_side=args.message_side)
        target_set = safe_path_component(os.path.splitext(os.path.basename(args.targets_file))[0])
    elif args.field_paths:
        targets = load_avp_paths_file(args.field_paths, message_side=args.message_side)
        target_set = args.message_side
    else:
        raise ValueError("Provide either --targets-file or --field-paths.")
    if not targets:
        raise ValueError("No targets loaded. Check target file and --message-side.")

    prompt_id = (
        safe_path_component(args.prompt_id)
        if args.prompt_id
        else infer_prompt_id(instruction_path, context_prompt_path, args.prompt_dir)
    )
    output_dir = args.output_dir or os.path.join(
        EVAL_DIR,
        "output",
        "large_scale",
        prompt_id,
        args.service,
        target_set,
    )
    ensure_dir(output_dir)

    print("=" * 80)
    print("Final Batch Analysis")
    print(f"  Targets: {len(targets)}")
    print(f"  Message side: {args.message_side}")
    print(f"  Target set: {target_set}")
    print(f"  Service: {args.service}")
    print(f"  Prompt ID: {prompt_id}")
    print(f"  Workers: {args.workers}")
    print(f"  Use specs: {args.use_specs}")
    print(f"  Output: {output_dir}")
    print("=" * 80)

    runner = LLMRunner(args.service)
    final_batch_analysis(
        samples=targets,
        instruction=instruction,
        context_prompt=context_prompt,
        output_dir=output_dir,
        runner=runner,
        use_specs=args.use_specs,
        specs_dir=args.specs_dir,
        max_workers=args.workers,
        force=args.force,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
