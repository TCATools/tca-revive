# -*- encoding: utf-8 -*-
'''
revive
./.. 可以解析多个mod, 子mod
a/a.go a/b.go会分为两个package分析
会对pacakge中的文件遍历分析, 部分规则需要pacakge完整信息, 更建议以package为维度进行分析
'''
import os
import json
import platform
import subprocess

PWD = os.getcwd()
WOORK_DIR = os.environ.get("RESULT_DIR")
SOURCE_DIR = os.environ.get("SOURCE_DIR")

def decode_str(text) -> str:
    try:
        return text.decode(encoding='UTF-8')
    except UnicodeDecodeError:
        return text.decode(encoding="gbk", errors="surrogateescape")

def get_task_params():
    """
    获取需要任务参数
    :return:
    """
    task_request_file = os.environ["TASK_REQUEST"]
    with open(task_request_file, "r") as rf:
        task_request = json.load(rf)
    task_params = task_request["task_params"]
    return task_params

class Revive():

    def __init__(self, params):
        self.params = params
        self.tool = self._get_tool()

    def _get_tool(self) -> str:
        system = platform.system()
        if system == "Linux":
            if platform.machine() == "aarch64":
                return os.path.join(PWD, "bin", "linux", "arm64", "revive")
            else:
                return os.path.join(PWD, "bin", "linux", "amd64", "revive")
        elif system == "Darwin":
            return os.path.join(PWD, "bin", "darwin", "amd64", "revive")
        elif system == "Windows":
            return os.path.join(PWD, "bin", "windows", "amd64", "revive.exe")
        else:
            raise Exception("未支持的系统平台或者无法识别的系统平台")
        
    def _get_config(self, rules) -> str:
        custom_config = os.environ.get("REVIVE_CONFIG")
        if custom_config and os.path.exists(os.path.join(SOURCE_DIR, custom_config)):
            return os.path.join(SOURCE_DIR, custom_config)
        tca_config = os.path.join(WOORK_DIR, "tca-default.toml")
        with open(tca_config, "a", encoding="utf-8") as fw:
            fw.write("ignoreGeneratedHeader = false\n")
            for rule in rules:
                rule_name = rule["name"]
                if rule_name == "syntax-error":
                    continue
                fw.write(f"[rule.{rule_name}]\n")
        return tca_config
        
    def analyze(self) -> list:
        print("当前使用的工具：" + self.tool)
        issues = []
        issues_file = os.path.join(WOORK_DIR, "revive-result.json")
        incr_scan = self.params["incr_scan"]
        want_suffix = (".go")
        scan_cmd = [self.tool, "-formatter", "json"]
        # rules去重
        rule_list = params["rule_list"]
        rule_names = set()
        rules = []
        for r in rule_list:
            if r["name"] not in rule_names:
                rule_names.add(r["name"])
                rules.append(r)
        # 如果未指定配置文件，则使用默认配置
        config_file = self._get_config(rules)
        scan_cmd.extend(["-config", config_file])
        toscan = ["./..."]
        # if incr_scan:
        #     with open(os.getenv("SCAN_FILES"), "r") as fr:
        #         task_file = json.load(fr)
        #     for file in task_file:
        #         if file.endswith(want_suffix):
        #             toscan.append(file)
        #     if len(" ".join(toscan)) > 100000:
        #         toscan = ["./..."]
        # else:
        #     toscan = ["./..."]
        # if not toscan:
        #     return issues
        scan_cmd.extend(toscan)
        print(scan_cmd)
        with open(issues_file, "w") as fw:
            sp = subprocess.Popen(scan_cmd, cwd=SOURCE_DIR, stdout=fw, stderr=subprocess.PIPE)
            _, stderr = sp.communicate(timeout=int(os.environ.get("TCA_TASK_TIMEOUT", "6000")))
        if stderr:
            stderr_str = decode_str(stderr)
            print(stderr)
            # 解析stderr中的错误信息
            for line in stderr_str.split('\n'):
                line = line.strip()
                if not line:
                    continue
                # 匹配格式: 2026/01/21 20:10:39 a/b.go:1:1: expected 'package', found a
                # 先按空格分割, 去掉时间戳部分
                time_parts = line.split(' ', 2)
                if len(time_parts) >= 3:
                    # 对剩余内容按冒号分割
                    content_parts = time_parts[2].split(':', 3)
                    if len(content_parts) >= 4:
                        file_path = content_parts[0].strip()
                        if not os.path.exists(os.path.join(SOURCE_DIR, file_path)):
                            continue
                        line_num = int(content_parts[1])
                        col_num = int(content_parts[2])
                        error_msg = content_parts[3].strip()
                        issues.append({
                            "path": file_path,
                            "rule": "syntax-error",
                            "msg": error_msg,
                            "line": line_num,
                            "column": col_num,
                        })
            # raise Exception(stderr.decode())
        # 分析异常时可能生成空文件导致读取异常
        try:
            with open(issues_file, "r") as fr:
                datas = json.load(fp=fr)
            print(datas)
            # 无问题时datas为None
            if not datas:
                return issues
        except Exception as err:
            print(f"解析结果异常: {err}")
            return issues
        for data in datas:
            issue_rule = data["RuleName"]
            issue_msg = data["Failure"]
            position = data["Position"]
            position_start = position["Start"]
            issue_file = position_start["Filename"]
            issue_line = position_start["Line"]
            issue_col = position_start["Column"]
            issues.append(
                {
                    "path": issue_file,
                    "rule": issue_rule,
                    "msg": issue_msg,
                    "line": issue_line,
                    "column": issue_col,
                }
            )
        return issues


if __name__ == "__main__":
    params = get_task_params()
    tool = Revive(params)
    result_file = os.path.join(WOORK_DIR, "result.json")
    issues = tool.analyze()
    with open(result_file, "w") as fw:
        json.dump(issues, fw, indent=2)
