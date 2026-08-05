# -*- encoding: utf-8 -*-
"""
check.py

参考 tca-plugin.py 的实现，脱离 TCA 环境变量依赖，本地直接调用
`bin/darwin/arm64/revive`，并使用 `scripts/output/arm64_rules.json`
生成的规则列表来构造 revive 配置文件，最后对 `scripts/testdate/`
下的 Go 源码进行分析。

产物：
- 配置文件： scripts/output/tca-default.toml
- 原始结果： scripts/output/revive-result.json
- 归一化结果：scripts/output/issues.json

使用方式：
    python3 scripts/check.py
"""

import json
import os
import subprocess
import sys
from typing import List


# 目录布局
SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, os.pardir))

# 固定使用 darwin/arm64 的二进制
REVIVE_BIN = os.path.join(PROJECT_ROOT, "bin", "darwin", "arm64", "revive")

# 输入：arm64 规则列表（由 get_rules.py 生成）
RULES_JSON = os.path.join(SCRIPT_DIR, "output", "arm64_rules.json")

# 输出目录 & 待扫描目录
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "output")
SOURCE_DIR = os.path.join(SCRIPT_DIR, "testdate")

CONFIG_FILE = os.path.join(OUTPUT_DIR, "tca-default.toml")
RAW_RESULT_FILE = os.path.join(OUTPUT_DIR, "revive-result.json")
ISSUES_FILE = os.path.join(OUTPUT_DIR, "issues.json")

# 与 tca-plugin.py 保持一致：syntax-error 不作为可配置规则写入 TOML
EXCLUDED_RULES = {"syntax-error"}


def decode_str(text: bytes) -> str:
    try:
        return text.decode(encoding="UTF-8")
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")


def load_rule_names() -> List[str]:
    """从 arm64_rules.json 中读取规则名列表（去重、排除 syntax-error）。"""
    if not os.path.isfile(RULES_JSON):
        raise FileNotFoundError(
            f"未找到规则列表文件：{RULES_JSON}\n"
            f"请先执行：python3 scripts/get_rules.py --export"
        )
    with open(RULES_JSON, "r", encoding="utf-8") as f:
        payload = json.load(f)

    names = [r["name"] for r in payload.get("rules", []) if r.get("name")]

    # 去重（保持顺序），并排除 syntax-error
    seen = set()
    unique_names: List[str] = []
    for n in names:
        if n in EXCLUDED_RULES or n in seen:
            continue
        seen.add(n)
        unique_names.append(n)

    return unique_names


def generate_config(rule_names: List[str], path: str) -> str:
    """按 tca-plugin.py 的风格生成 TOML 配置。"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fw:
        fw.write("ignoreGeneratedHeader = false\n")
        for rule_name in rule_names:
            fw.write(f"[rule.{rule_name}]\n")
    print(f"[config] 已生成配置文件：{path}（启用 {len(rule_names)} 条规则）")
    return path


def parse_stderr_syntax_errors(stderr_str: str) -> List[dict]:
    """解析 revive stderr 中的语法错误行，格式：
    `2026/01/21 20:10:39 a/b.go:1:1: expected 'package', found a`
    """
    issues: List[dict] = []
    for line in stderr_str.split("\n"):
        line = line.strip()
        if not line:
            continue
        time_parts = line.split(" ", 2)
        if len(time_parts) < 3:
            continue
        content_parts = time_parts[2].split(":", 3)
        if len(content_parts) < 4:
            continue
        file_path = content_parts[0].strip()
        if not os.path.exists(os.path.join(SOURCE_DIR, file_path)):
            continue
        try:
            line_num = int(content_parts[1])
            col_num = int(content_parts[2])
        except ValueError:
            continue
        error_msg = content_parts[3].strip()
        issues.append(
            {
                "path": file_path,
                "rule": "syntax-error",
                "msg": error_msg,
                "line": line_num,
                "column": col_num,
            }
        )
    return issues


def run_revive(config_file: str) -> List[dict]:
    """调用 revive 分析 SOURCE_DIR 下的所有 Go 包，返回归一化 issues。"""
    if not os.path.isfile(REVIVE_BIN):
        raise FileNotFoundError(f"未找到 revive 二进制：{REVIVE_BIN}")
    if not os.access(REVIVE_BIN, os.X_OK):
        raise PermissionError(f"revive 无可执行权限：{REVIVE_BIN}")
    if not os.path.isdir(SOURCE_DIR):
        raise FileNotFoundError(f"未找到待扫描目录：{SOURCE_DIR}")

    scan_cmd = [
        REVIVE_BIN,
        "-formatter",
        "json",
        "-config",
        config_file,
        "./...",
    ]
    print(f"[scan] 执行命令：{' '.join(scan_cmd)}")
    print(f"[scan] 工作目录：{SOURCE_DIR}")

    issues: List[dict] = []
    with open(RAW_RESULT_FILE, "w", encoding="utf-8") as fw:
        sp = subprocess.Popen(
            scan_cmd,
            cwd=SOURCE_DIR,
            stdout=fw,
            stderr=subprocess.PIPE,
        )
        _, stderr = sp.communicate(
            timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "6000"))
        )

    if stderr:
        stderr_str = decode_str(stderr)
        if stderr_str.strip():
            print("[scan] stderr:")
            print(stderr_str)
        issues.extend(parse_stderr_syntax_errors(stderr_str))

    try:
        with open(RAW_RESULT_FILE, "r", encoding="utf-8") as fr:
            datas = json.load(fr)
    except Exception as err:
        print(f"[scan] 解析结果异常：{err}")
        return issues

    if not datas:
        return issues

    for data in datas:
        position_start = data["Position"]["Start"]
        issues.append(
            {
                "path": position_start["Filename"],
                "rule": data["RuleName"],
                "msg": data["Failure"],
                "line": position_start["Line"],
                "column": position_start["Column"],
            }
        )
    return issues


def main() -> int:
    try:
        rule_names = load_rule_names()
    except FileNotFoundError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 1

    if not rule_names:
        print("错误：可用规则集合为空，请检查规则列表文件。", file=sys.stderr)
        return 1

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    config_file = generate_config(rule_names, CONFIG_FILE)

    try:
        issues = run_revive(config_file)
    except (FileNotFoundError, PermissionError) as e:
        print(f"错误：{e}", file=sys.stderr)
        return 1

    with open(ISSUES_FILE, "w", encoding="utf-8") as fw:
        json.dump(issues, fw, ensure_ascii=False, indent=2)

    print()
    print("=" * 72)
    print(f"扫描完成，共发现 {len(issues)} 个问题")
    print(f"原始结果：{RAW_RESULT_FILE}")
    print(f"归一化结果：{ISSUES_FILE}")
    print("=" * 72)

    # 简要汇总：按规则分组统计
    if issues:
        from collections import Counter

        counter = Counter(i["rule"] for i in issues)
        print("按规则统计：")
        for rule, cnt in counter.most_common():
            print(f"  {rule:35s}  {cnt}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
