"""Protocol-level analysis of all S6a and Cx fields.

By default this script:
1. loads the full S6a + Cx field paths (both Request and Answer messages,
   from s6a_field_paths.txt and cx_field_paths.txt);
2. uses the final LENS prompts (instruction + context prompt) as
   the analysis prompt; and
3. runs the LLM pipeline (context preparation + exploit assessment when a
   context prompt is available, otherwise exploit-assessment only) over the
   fields and writes per-field responses, a summary, and token-usage
   statistics.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List, Optional, Tuple

if __package__ is None or __package__ == "":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from .common import EVAL_DIR, ensure_dir, read_text, timestamp, write_json
from .llm import LLMRunner
from .pipeline import exploit_assessment, final_batch_analysis
from .samples import Sample, load_avp_paths_file


DEFAULT_S6A_FILE = os.path.join(
    EVAL_DIR, "data", "diameter", "s6a_field_paths.txt"
)
DEFAULT_CX_FILE = os.path.join(
    EVAL_DIR, "data", "diameter", "cx_field_paths.txt"
)


def load_protocol_fields(s6a_file: str, cx_file: str, message_side: str = "all") -> List[Sample]:
    s6a = load_avp_paths_file(s6a_file, message_side=message_side)
    for i, sample in enumerate(s6a, 1):
        sample.number = 200000 + i
        sample.input_key = f"s6a_{message_side}_{i:04d}_{sample.message_abbr}"
    cx = load_avp_paths_file(cx_file, message_side=message_side)
    for i, sample in enumerate(cx, 1):
        sample.number = 300000 + i
        sample.input_key = f"cx_{message_side}_{i:04d}_{sample.message_abbr}"
    return s6a + cx


def resolve_prompts(
    prompt_dir: Optional[str],
    instruction_file: Optional[str],
    context_prompt_file: Optional[str],
) -> Tuple[str, Optional[str]]:
    # Explicit per-file overrides take precedence.
    if instruction_file:
        instruction = read_text(instruction_file)
        context_prompt = read_text(context_prompt_file) if context_prompt_file else None
        return instruction, context_prompt
    if not prompt_dir:
        raise ValueError("either --prompt-dir or --instruction-file must be provided")
    # LENS evaluation layout: instruction_used.txt + context_prompt_used.txt
    lens_instruction = os.path.join(prompt_dir, "instruction_used.txt")
    lens_context = os.path.join(prompt_dir, "context_prompt_used.txt")
    if os.path.exists(lens_instruction):
        instruction = read_text(lens_instruction)
        context_prompt = read_text(lens_context) if os.path.exists(lens_context) else None
        return instruction, context_prompt
    # prompt_construction layout: final_instruction.txt + final_context_prompt.txt
    instruction_path = os.path.join(prompt_dir, "final_instruction.txt")
    context_path = os.path.join(prompt_dir, "final_context_prompt.txt")
    if os.path.exists(instruction_path):
        instruction = read_text(instruction_path)
        context_prompt = read_text(context_path) if os.path.exists(context_path) else None
        return instruction, context_prompt
    raise FileNotFoundError(
        f"could not locate instruction_used.txt or final_instruction.txt "
        f"under {prompt_dir}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Large-scale assessment on all 766 S6a+Cx fields using final LENS prompts."
    )
    parser.add_argument("--s6a-file", default=DEFAULT_S6A_FILE)
    parser.add_argument("--cx-file", default=DEFAULT_CX_FILE)
    parser.add_argument("--message-side", choices=["request", "answer", "all"], default="all")
    parser.add_argument("--prompt-dir", default=None,
                        help="Directory containing instruction_used.txt + context_prompt_used.txt "
                             "(LENS evaluation layout) OR final_instruction.txt + final_context_prompt.txt "
                             "(prompt_construction layout). Required unless --instruction-file is provided.")
    parser.add_argument("--instruction-file", default=None,
                        help="Direct path to the instruction (PoC) prompt file. Overrides --prompt-dir.")
    parser.add_argument("--context-prompt-file", default=None,
                        help="Direct path to the context-prompt file. Used together with --instruction-file.")
    parser.add_argument("--service", default="gpt5.4")
    parser.add_argument("--workers", type=int, default=20)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    samples = load_protocol_fields(args.s6a_file, args.cx_file, message_side=args.message_side)
    instruction, context_prompt = resolve_prompts(
        args.prompt_dir, args.instruction_file, args.context_prompt_file,
    )
    prompt_label = (
        os.path.basename(args.instruction_file).rsplit(".", 1)[0]
        if args.instruction_file
        else os.path.basename(args.prompt_dir.rstrip(os.sep))
    )
    output_dir = args.output_dir or os.path.join(
        EVAL_DIR, "output", args.service, "protocol_level_findings",
        f"{prompt_label}_{timestamp()}"
    )
    ensure_dir(output_dir)

    print("=" * 80)
    print(f"Protocol-level analysis ({args.message_side})")
    print(f"  s6a {args.message_side} fields: {sum(1 for s in samples if s.interface=='s6a')}")
    print(f"  cx  {args.message_side} fields: {sum(1 for s in samples if s.interface=='cx')}")
    print(f"  total fields: {len(samples)}")
    if args.instruction_file:
        print(f"  instruction file: {args.instruction_file}")
        print(f"  context prompt file: {args.context_prompt_file or '<none, exploit-only>'}")
    else:
        print(f"  prompt dir: {args.prompt_dir}")
        print(f"  context prompt: {'<none, exploit-only>' if not context_prompt else 'enabled'}")
    print(f"  service: {args.service}  workers: {args.workers}")
    print(f"  output: {output_dir}")
    print("=" * 80)

    runner = LLMRunner(args.service)
    started = time.time()
    if context_prompt:
        results = final_batch_analysis(
            samples=samples,
            instruction=instruction,
            context_prompt=context_prompt,
            output_dir=output_dir,
            runner=runner,
            max_workers=args.workers,
            force=args.force,
        )
    else:
        results = exploit_assessment(
            samples=samples,
            instruction=instruction,
            output_dir=os.path.join(output_dir, "exploit_assessment"),
            runner=runner,
            max_workers=args.workers,
            force=args.force,
        )
    elapsed = time.time() - started

    classes = {"ATTACK": 0, "SAFE": 0, "UNKNOWN": 0, "OTHER": 0}
    for r in results:
        c = r.get("classification") or "UNKNOWN"
        classes[c if c in classes else "OTHER"] += 1

    by_iface_msg = {}
    for r in results:
        iface = r.get("interface") or "?"
        msg = r.get("message_full") or "?"
        side = "Request" if msg.endswith("Request") else ("Answer" if msg.endswith("Answer") else "?")
        key = (iface, side)
        slot = by_iface_msg.setdefault(key, {"ATTACK": 0, "SAFE": 0, "UNKNOWN": 0, "OTHER": 0})
        c = r.get("classification") or "UNKNOWN"
        slot[c if c in slot else "OTHER"] += 1

    summary = {
        "prompt_dir": args.prompt_dir,
        "service": args.service,
        "message_side": args.message_side,
        "total_fields": len(results),
        "classification_counts": classes,
        "classification_by_iface_side": {f"{k[0]}-{k[1]}": v for k, v in sorted(by_iface_msg.items())},
        "elapsed_seconds": elapsed,
        "token_stats": runner.get_stats(),
        "output_dir": output_dir,
    }
    write_json(os.path.join(output_dir, "protocol_level_findings_summary.json"), summary)

    print("\n=== Protocol-level findings summary ===")
    for k, v in classes.items():
        print(f"  {k}: {v}")
    print(f"  elapsed: {elapsed:.1f}s")
    print(f"  tokens: {summary['token_stats']}")
    print(f"  output: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
