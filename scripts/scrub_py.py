#!/usr/bin/env python3
"""
scrub_py.py — 洗掉 bla-agents 注入 Python 源码的恒假死分支（零依赖）。

只处理实测形状：
    if depth > 0 and (<恒假A>) or (<恒假B>):
        <body>
判定：条件里出现 `_RUNTIME`/`_STATE`/`_SEED` 种子变量 + `0xFFFFFFFF` 算术。
求值：用 ast 白名单（只允许整数算术/位运算/比较/布尔），种子从同文件
      `NAME = 0x.. | 1` 抓；求值为 False 则整块（if + 更深缩进 body）删除。

用法:
    python scrub_py.py <file.py>            # 只报告
    python scrub_py.py <file.py> --apply    # 就地写回
"""
import ast
import re
import sys
from pathlib import Path

SEED_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*\|\s*1\s*$", re.M)
IF_RE = re.compile(r"^(\s*)if\s+depth\s*>\s*0\s+and\s+(.+):\s*$")
ALLOWED = (
    ast.Expression, ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
    ast.Constant, ast.Name, ast.Load, ast.And, ast.Or, ast.Not,
    ast.Add, ast.Sub, ast.Mult, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.USub, ast.UAdd, ast.Invert,
    ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq,
)


def collect_seeds(src: str) -> dict:
    seeds = {}
    for m in SEED_RE.finditer(src):
        seeds[m.group(1)] = int(m.group(2), 0) | 1
    return seeds


def safe_eval(expr: str, seeds: dict):
    tree = ast.parse(expr, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED):
            return None
        if isinstance(node, ast.Name) and node.id not in seeds:
            return None
    try:
        return eval(compile(tree, "<scrub>", "eval"), {"__builtins__": {}}, dict(seeds))
    except Exception:
        return None


def body_end(lines, start_idx, indent_len):
    """返回 (body_start, body_end_exclusive)：连续比 indent_len 更深的行。"""
    i = start_idx + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        cur = len(line) - len(line.lstrip())
        if cur <= indent_len:
            break
        i += 1
    return start_idx + 1, i


def scrub(src: str, verbose: bool):
    lines = src.splitlines(keepends=True)
    seeds = collect_seeds(src)
    out, i, hits, misses = [], 0, 0, 0
    while i < len(lines):
        m = IF_RE.match(lines[i])
        if not m:
            out.append(lines[i]); i += 1; continue
        indent, cond = m.group(1), m.group(2)
        # `(A) or (B)` → 取整体；`and (...)` 已在正则外
        value = safe_eval(cond, seeds)
        if value is False:
            bs, be = body_end(lines, i, len(indent))
            if verbose:
                print(f"  dead @L{i+1}  body={be-bs} lines  {cond[:60]}...")
            out.append(f"{indent}pass  # bla-scrubbed\n")
            i = be; hits += 1; continue
        if value is None:
            misses += 1
        out.append(lines[i]); i += 1
    return "".join(out), hits, misses, len(seeds)


def main():
    if len(sys.argv) < 2:
        print("usage: python scrub_py.py <file.py> [--apply] [--verbose]")
        return 1
    path = Path(sys.argv[1])
    apply_ = "--apply" in sys.argv
    verbose = "--verbose" in sys.argv
    src = path.read_text(encoding="utf-8")
    out, hits, misses, nseeds = scrub(src, verbose)
    print(f"seeds={nseeds}  dead={hits}  unknown={misses}")
    if not apply_:
        print("(dry run; add --apply to write)")
        return 0
    path.write_text(out, encoding="utf-8")
    print(f"written: {len(src)} -> {len(out)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
