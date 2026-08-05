#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
读取 bin/darwin/amd64/README.md 与 bin/darwin/arm64/README.md 中的
`## Available Rules` 章节，解析规则表格，并比较两个版本的规则差异。

使用方式：
    # 打印对比报告（默认行为）
    python3 scripts/get_rules.py

    # 同时把 arm64 的规则列表导出到默认目录 scripts/output/
    #   - arm64_rules.json  （完整字段，供其他脚本消费）
    #   - arm64_rules.txt   （每行一个规则名，简单文本）
    python3 scripts/get_rules.py --export

    # 自定义导出路径 / 只导出 JSON 或 TXT
    python3 scripts/get_rules.py --export-json /tmp/rules.json
    python3 scripts/get_rules.py --export-txt  /tmp/rules.txt
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Tuple


# 项目根目录（本脚本位于 <root>/scripts/ 下）
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

AMD64_README = os.path.join(PROJECT_ROOT, "bin", "darwin", "amd64", "README.md")
ARM64_README = os.path.join(PROJECT_ROOT, "bin", "darwin", "arm64", "README.md")

# 默认导出目录 & 文件
DEFAULT_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
DEFAULT_JSON_PATH = os.path.join(DEFAULT_OUTPUT_DIR, "arm64_rules.json")
DEFAULT_TXT_PATH = os.path.join(DEFAULT_OUTPUT_DIR, "arm64_rules.txt")

# 规则名从形如 [`rule-name`](./RULES_DESCRIPTIONS.md#rule-name) 的第一列中提取
RULE_NAME_RE = re.compile(r"\[`([^`]+)`\]")


def extract_available_rules_section(md_text: str) -> str:
    """从整个 README 文本中截取 `## Available Rules` 章节的内容（到下一个 `## ` 之前）。"""
    lines = md_text.splitlines()
    start = -1
    for i, line in enumerate(lines):
        if line.strip() == "## Available Rules":
            start = i + 1
            break
    if start == -1:
        return ""

    end = len(lines)
    for j in range(start, len(lines)):
        # 下一个二级标题作为结束边界
        if lines[j].startswith("## ") and lines[j].strip() != "## Available Rules":
            end = j
            break
    return "\n".join(lines[start:end])


def parse_rules_table(section_text: str) -> Dict[str, Dict[str, str]]:
    """
    解析 Markdown 表格，返回 {规则名: {"config": ..., "description": ..., "golint": ..., "typed": ...}}
    """
    rules: Dict[str, Dict[str, str]] = {}
    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        # 只处理表格数据行：以 | 开头，且包含 rule 链接
        if not line.startswith("|"):
            continue
        # 跳过表头及分隔线
        if line.startswith("| Name") or set(line.replace("|", "").strip()) <= set("-: "):
            continue

        # 将首尾的 | 去掉后按 | 分割为列
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 5:
            continue

        name_cell, config_cell, desc_cell, golint_cell, typed_cell = cells[:5]
        m = RULE_NAME_RE.search(name_cell)
        if not m:
            continue
        name = m.group(1)
        rules[name] = {
            "config": config_cell,
            "description": desc_cell,
            "golint": golint_cell,
            "typed": typed_cell,
        }
    return rules


def load_rules(path: str) -> Dict[str, Dict[str, str]]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"未找到 README：{path}")
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    section = extract_available_rules_section(text)
    if not section:
        raise ValueError(f"文件中未找到 `## Available Rules` 章节：{path}")
    return parse_rules_table(section)


def compare_rules(
    amd_rules: Dict[str, Dict[str, str]],
    arm_rules: Dict[str, Dict[str, str]],
) -> Tuple[List[str], List[str], List[Tuple[str, Dict[str, Tuple[str, str]]]]]:
    """
    返回：
        only_in_amd:   仅 amd64 中存在的规则名
        only_in_arm:   仅 arm64 中存在的规则名
        diff_details:  规则名相同但字段有差异的列表
                       [(rule_name, {field: (amd_value, arm_value)})]
    """
    amd_names = set(amd_rules)
    arm_names = set(arm_rules)

    only_in_amd = sorted(amd_names - arm_names)
    only_in_arm = sorted(arm_names - amd_names)

    diff_details: List[Tuple[str, Dict[str, Tuple[str, str]]]] = []
    for name in sorted(amd_names & arm_names):
        a, b = amd_rules[name], arm_rules[name]
        field_diffs: Dict[str, Tuple[str, str]] = {}
        for field in ("config", "description", "golint", "typed"):
            if a.get(field, "") != b.get(field, ""):
                field_diffs[field] = (a.get(field, ""), b.get(field, ""))
        if field_diffs:
            diff_details.append((name, field_diffs))

    return only_in_amd, only_in_arm, diff_details


def print_report(
    amd_rules: Dict[str, Dict[str, str]],
    arm_rules: Dict[str, Dict[str, str]],
    only_in_amd: List[str],
    only_in_arm: List[str],
    diff_details: List[Tuple[str, Dict[str, Tuple[str, str]]]],
) -> None:
    print("=" * 72)
    print("Revive Available Rules 对比报告 (amd64 vs arm64)")
    print("=" * 72)
    print(f"amd64 规则总数: {len(amd_rules)}")
    print(f"arm64 规则总数: {len(arm_rules)}")
    print(f"仅 amd64 存在: {len(only_in_amd)}")
    print(f"仅 arm64 存在: {len(only_in_arm)}")
    print(f"两端都有但字段不同: {len(diff_details)}")
    print()

    print("-" * 72)
    print("[仅在 amd64 中存在的规则]")
    print("-" * 72)
    if only_in_amd:
        for n in only_in_amd:
            print(f"  + {n}")
    else:
        print("  （无）")
    print()

    print("-" * 72)
    print("[仅在 arm64 中存在的规则]")
    print("-" * 72)
    if only_in_arm:
        for n in only_in_arm:
            print(f"  + {n}")
    else:
        print("  （无）")
    print()

    print("-" * 72)
    print("[两端都有但字段不同的规则]")
    print("-" * 72)
    if diff_details:
        for name, fields in diff_details:
            print(f"* {name}")
            for field, (av, bv) in fields.items():
                print(f"    - {field}:")
                print(f"        amd64: {av}")
                print(f"        arm64: {bv}")
    else:
        print("  （无）")


def export_rules_json(rules: Dict[str, Dict[str, str]], path: str, source: str) -> None:
    """将规则列表导出为 JSON，方便其他脚本按结构化方式消费。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    payload = {
        "source": source,
        "count": len(rules),
        "rules": [
            {
                "name": name,
                "config": rules[name].get("config", ""),
                "description": rules[name].get("description", ""),
                "golint": rules[name].get("golint", ""),
                "typed": rules[name].get("typed", ""),
            }
            for name in sorted(rules.keys())
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[export] JSON 已写入: {path} （{len(rules)} 条规则）")


def export_rules_txt(rules: Dict[str, Dict[str, str]], path: str) -> None:
    """将规则名以每行一个的形式写入文本文件，方便 shell/awk 等工具消费。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for name in sorted(rules.keys()):
            f.write(name + "\n")
    print(f"[export] TXT  已写入: {path} （{len(rules)} 条规则）")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="比较 amd64/arm64 两份 README 中的 Available Rules，并可导出 arm64 规则列表。",
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help=f"同时导出 arm64 规则到默认位置：{DEFAULT_JSON_PATH} 与 {DEFAULT_TXT_PATH}",
    )
    parser.add_argument(
        "--export-json",
        metavar="PATH",
        default=None,
        help="将 arm64 规则以 JSON 格式导出到指定文件（可与 --export-txt 同时使用）。",
    )
    parser.add_argument(
        "--export-txt",
        metavar="PATH",
        default=None,
        help="将 arm64 规则名列表（每行一个）导出到指定文件。",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="不打印对比报告（仅执行导出）。",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    try:
        amd_rules = load_rules(AMD64_README)
        arm_rules = load_rules(ARM64_README)
    except (FileNotFoundError, ValueError) as e:
        print(f"错误：{e}", file=sys.stderr)
        return 1

    only_in_amd, only_in_arm, diff_details = compare_rules(amd_rules, arm_rules)
    if not args.quiet:
        print_report(amd_rules, arm_rules, only_in_amd, only_in_arm, diff_details)

    # 处理导出
    json_path = args.export_json
    txt_path = args.export_txt
    if args.export:
        json_path = json_path or DEFAULT_JSON_PATH
        txt_path = txt_path or DEFAULT_TXT_PATH

    if json_path or txt_path:
        if not args.quiet:
            print()
            print("-" * 72)
            print("[导出 arm64 规则列表]")
            print("-" * 72)
        if json_path:
            export_rules_json(arm_rules, json_path, source=ARM64_README)
        if txt_path:
            export_rules_txt(arm_rules, txt_path)

    # 若存在任何差异，以非零码退出便于在 CI 中使用
    if only_in_amd or only_in_arm or diff_details:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
