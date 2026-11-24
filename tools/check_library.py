"""BatterySenti 社区设备库的检查脚本。

每个 PR 都会由 GitHub Actions 自动运行它；提交者也可以在本地先跑一遍：
    python tools/check_library.py          只检查
    python tools/check_library.py --fix    按现有文件重新生成 library.json，再检查

它检查的是"格式和证据对不对得上"，不能判断一条报文是不是真的只读。
那一步要靠人工审核，见 REVIEW.md。

检查内容（和 BatterySenti 程序下载设备库时做的检查一致，另加了几条隐私检查）：
1. library.json 的格式版本、文件路径、SHA-256 都和仓库里的文件一致。
2. 每个设备定义：id 格式、VID/PID、读取方式、报文长度、必须附抓包证据。
3. 请求字节必须和证据里"电脑发给设备"的那一帧一字不差；回复开头必须和证据里设备的回复一致。
4. 禁止列表里的设备不收。
5. 隐私：证据文件只能包含定义里引用到的帧；不能上传原始抓包（.pcap / .pcapng）。
6. 仓库里不能出现其他类型的文件。
"""

import csv
import hashlib
import io
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = 1
LIBRARY_NAME = "BatterySenti 社区设备库"
SAFE_ID = re.compile(r"^[a-z0-9_]{3,64}$")
SAFE_PATH = re.compile(r"^[A-Za-z0-9_\-./]+$")
MAX_REPORT_BYTES = 91
CSV_FIELDS = ["frame", "time", "device", "dir", "ep", "transfer", "request",
              "report_type", "report_id", "interface", "length", "hex"]
# 和程序里的禁止列表保持一致
DENY_LIST = {("373B", "12AE"), ("35D8", "012E"), ("0B05", "19AF")}
# 仓库里允许出现的文件（其余一律报错）
ALLOWED_TOP = {"README.md", "CONTRIBUTING.md", "REVIEW.md", "LICENSE", "library.json", ".gitignore", ".gitattributes"}
ALLOWED_DIRS = ("devices/", "captures/", "tools/", ".github/")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hexstr(text):
    return "".join(ch for ch in str(text).lower() if ch in "0123456789abcdef")


def vidpid(text):
    return f"{int(str(text), 16):04X}"


class Report:
    def __init__(self):
        self.errors = []

    def err(self, where, msg):
        self.errors.append(f"{where}: {msg}")


# ---------------- library.json ----------------
def build_index():
    entries = []
    for dev_file in sorted((ROOT / "devices").glob("*.json")):
        ev = sorted((ROOT / "captures" / dev_file.stem).glob("*.extracted.csv"))
        entries.append({
            "file": dev_file.relative_to(ROOT).as_posix(), "sha256": sha256(dev_file),
            "evidence": [{"file": e.relative_to(ROOT).as_posix(), "sha256": sha256(e)} for e in ev],
        })
    return {"schema": SCHEMA, "name": LIBRARY_NAME, "devices": entries}


def write_index():
    data = json.dumps(build_index(), ensure_ascii=False, indent=2) + "\n"
    (ROOT / "library.json").write_text(data, encoding="utf-8", newline="\n")


def safe_rel(rep, path, prefix):
    if not isinstance(path, str) or not SAFE_PATH.match(path) or ".." in path or not path.startswith(prefix):
        rep.err("library.json", f"文件路径不安全：{path}")
        return None
    return path


def check_index(rep):
    try:
        index = json.loads((ROOT / "library.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        rep.err("library.json", f"读不了：{e}")
        return
    if index.get("schema") != SCHEMA:
        rep.err("library.json", f"schema 必须是 {SCHEMA}")
    listed = set()
    for entry in index.get("devices", []):
        files = [(entry.get("file"), entry.get("sha256"), "devices/")]
        files += [(e.get("file"), e.get("sha256"), "captures/") for e in entry.get("evidence", [])]
        for rel, digest, prefix in files:
            if safe_rel(rep, rel, prefix) is None:
                continue
            listed.add(rel)
            path = ROOT / rel
            if not path.is_file():
                rep.err("library.json", f"列出的文件不存在：{rel}")
            elif sha256(path) != digest:
                rep.err("library.json", f"{rel} 的 SHA-256 和文件对不上（运行 python tools/check_library.py --fix）")
    actual = {p.relative_to(ROOT).as_posix() for p in (ROOT / "devices").glob("*.json")}
    actual |= {p.relative_to(ROOT).as_posix() for p in (ROOT / "captures").glob("*/*.extracted.csv")}
    for rel in sorted(actual - listed):
        rep.err("library.json", f"没有登记这个文件：{rel}（运行 python tools/check_library.py --fix）")


# ---------------- 设备定义 ----------------
def load_evidence(rep, where, capture_rel):
    """读取抓包证据。定义里写的是原始抓包的路径，证据是旁边同名的 .extracted.csv。"""
    if not isinstance(capture_rel, str) or not SAFE_PATH.match(capture_rel) or ".." in capture_rel \
            or not capture_rel.startswith(f"captures/{where}/"):
        rep.err(where, f"capture 路径必须在 captures/{where}/ 下：{capture_rel}")
        return None, None
    p = Path(capture_rel)
    csv_path = ROOT / p.with_name(p.stem + ".extracted.csv")
    if not csv_path.is_file():
        rep.err(where, f"找不到证据文件：{csv_path.relative_to(ROOT).as_posix()}")
        return None, None
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != CSV_FIELDS:
            rep.err(where, f"{csv_path.name} 的表头不对，应为：{','.join(CSV_FIELDS)}")
            return None, None
        rows = list(reader)
    return csv_path, rows


def check_reading(rep, where, block, used_frames, label):
    req, resp = block.get("request") or {}, block.get("response") or {}
    req_hex = hexstr(req.get("hex", ""))
    prefix = hexstr(resp.get("match_prefix", ""))
    if not req_hex:
        rep.err(where, f"{label}: request.hex 是空的")
    if len(req_hex) // 2 > MAX_REPORT_BYTES:
        rep.err(where, f"{label}: 请求报文太长")
    if req.get("method") not in ("feature", "output"):
        rep.err(where, f"{label}: request.method 只能是 feature 或 output")
    if resp.get("method") not in ("feature", "input"):
        rep.err(where, f"{label}: response.method 只能是 feature 或 input")
    if len(prefix) < 2:
        rep.err(where, f"{label}: response.match_prefix 至少 1 个字节")
    captures = [s for s in block.get("sources") or [] if s.get("type", "capture" if "capture" in s else "reference") == "capture"]
    if not captures:
        rep.err(where, f"{label}: 必须附带抓包证据（sources 里 type 为 capture 的来源）")
    for src in captures:
        csv_path, rows = load_evidence(rep, where, src.get("capture"))
        if rows is None:
            continue
        by_frame = {}
        for r in rows:
            try:
                by_frame[int(r["frame"])] = r
            except (TypeError, ValueError):
                rep.err(where, f"{csv_path.name} 里有不是数字的帧号")
        try:
            fr_req = int(src["request_frame"])
        except (KeyError, TypeError, ValueError):
            rep.err(where, f"{label}: 来源缺少 request_frame")
            continue
        r = by_frame.get(fr_req)
        if r is None or r["dir"] != "OUT" or hexstr(r["hex"]) != req_hex:
            rep.err(where, f"{label}: {csv_path.name} 第 {fr_req} 帧和 request.hex 对不上")
        used_frames.setdefault(csv_path, set()).add(fr_req)
        if src.get("response_frame") is not None:
            fr_resp = int(src["response_frame"])
            a = by_frame.get(fr_resp)
            if a is None or a["dir"] != "IN" or not hexstr(a["hex"]).startswith(prefix):
                rep.err(where, f"{label}: {csv_path.name} 第 {fr_resp} 帧和 response.match_prefix 对不上")
            used_frames[csv_path].add(fr_resp)
        else:
            rep.err(where, f"{label}: 来源要写 response_frame，审核时才能看到设备的回复")


def check_device(rep, dev_file):
    where = dev_file.stem
    try:
        dev = json.loads(dev_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        rep.err(where, f"JSON 格式错误：{e}")
        return {}
    if not SAFE_ID.match(str(dev.get("id", ""))):
        rep.err(where, "id 只能用小写字母、数字和下划线，3 到 64 个字符")
    elif dev["id"] != where:
        rep.err(where, f"文件名必须和 id 一样：devices/{dev['id']}.json")
    for key in ("name", "kind", "vid", "pid", "battery_read"):
        if key not in dev:
            rep.err(where, f"缺少 {key}")
    if not dev.get("author"):
        rep.err(where, "author 写上你的 GitHub 用户名")
    try:
        vp = (vidpid(dev["vid"]), vidpid(dev["pid"]))
        if vp in DENY_LIST:
            rep.err(where, "这个设备在禁止列表里，不收")
    except (KeyError, ValueError):
        rep.err(where, "vid / pid 必须是十六进制，例如 \"3554\"")
    if not dev.get("collections") and not (dev.get("usage_page") and dev.get("usage")):
        rep.err(where, "缺少 collections 或 usage_page/usage")
    used = {}
    br = dev.get("battery_read") or {}
    if br:
        check_reading(rep, where, br, used, "battery_read")
        try:
            int(br["response"]["battery_offset"]), int(br["response"]["length"])
        except (KeyError, TypeError, ValueError):
            rep.err(where, "battery_read.response 缺少 battery_offset 或 length")
        if br.get("charging_read"):
            ch = br["charging_read"]
            check_reading(rep, where, ch, used, "charging_read")
            r = ch.get("response") or {}
            if "offset" not in r or not r.get("values"):
                rep.err(where, "charging_read.response 缺少 offset 或 values")
    return used


def check_privacy(rep, used_by_device):
    used = {}
    for frames in used_by_device:
        for path, fr in frames.items():
            used.setdefault(path, set()).update(fr)
    for csv_path in sorted((ROOT / "captures").glob("*/*.extracted.csv")):
        rel = csv_path.relative_to(ROOT).as_posix()
        with open(csv_path, newline="", encoding="utf-8") as f:
            frames = {int(r["frame"]) for r in csv.DictReader(f) if str(r.get("frame", "")).isdigit()}
        extra = frames - used.get(csv_path, set())
        if extra:
            rep.err(rel, f"有 {len(extra)} 帧没被任何定义引用，必须删掉（隐私：可能含按键或序列号）")


def check_files(rep):
    for p in sorted(ROOT.rglob("*")):
        if p.is_dir() or ".git" in p.relative_to(ROOT).parts[:1]:
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel.startswith(".github/"):
            continue
        if p.suffix.lower() in (".pcap", ".pcapng"):
            rep.err(rel, "不要上传原始抓包，只上传裁剪后的 .extracted.csv")
        elif rel in ALLOWED_TOP or p.name == ".gitkeep":
            continue
        elif rel.startswith("devices/") and p.suffix == ".json" and rel.count("/") == 1:
            continue
        elif rel.startswith("captures/") and p.name.endswith(".extracted.csv") and rel.count("/") == 2:
            continue
        elif rel.startswith("tools/") and p.suffix == ".py":
            continue
        else:
            rep.err(rel, "这个位置不允许放这种文件")


def main(argv):
    if "--fix" in argv:
        write_index()
        print("已重新生成 library.json")
    rep = Report()
    check_files(rep)
    check_index(rep)
    used = [check_device(rep, f) for f in sorted((ROOT / "devices").glob("*.json"))]
    check_privacy(rep, used)
    n = len(list((ROOT / "devices").glob("*.json")))
    if rep.errors:
        print(f"检查没通过（{len(rep.errors)} 个问题）：")
        for e in rep.errors:
            print("  - " + e)
        return 1
    print(f"检查通过：{n} 个设备定义。")
    print("注意：脚本不能判断报文是不是只读，合并前请按 REVIEW.md 人工审核。")
    return 0


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.exit(main(sys.argv[1:]))
