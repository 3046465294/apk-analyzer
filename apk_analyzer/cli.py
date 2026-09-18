"""
apk-analyzer 命令行入口。

用法：
    python analyze.py <file.apk>                 # 概览 + DEX 完整性验证
    python analyze.py <file.apk> --list 40       # 额外列出前 40 个归档条目
    python analyze.py <file.apk> --json          # 输出 JSON（便于接入 CI）
    python analyze.py <file.apk> --explain-checksum   # 校验和深度诊断

退出码：
    0  分析完成且所有完整性校验通过
    1  分析完成但存在完整性失败（可用于 CI 卡门）
    2  文件无法解析
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from apk_analyzer import compare as compare_mod
from apk_analyzer import dexfmt, zipfmt


# ----------------------------------------------------- 控制台编码 ----------
# Windows 中文控制台默认代码页是 GBK，直接 print 「✓ ✗ ⚠」会抛
# UnicodeEncodeError 并中断整个分析（第一次实跑就是这么崩的）。
# 这里先把标准输出切到 UTF-8；实在切不了的环境用 --ascii 退化。
USE_ASCII = False


def setup_console() -> None:
    """把 stdout/stderr 切到 UTF-8，失败则退化为可替换，保证永不因编码中断。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _mark(kind: str) -> str:
    table = (
        {"ok": "[OK]", "fail": "[FAIL]", "warn": "[!]"}
        if USE_ASCII
        else {"ok": "✓", "fail": "✗", "warn": "⚠"}
    )
    return table[kind]


# ---------------------------------------------------------------- 渲染 ----
def _hr(char: str = "", width: int = 78) -> str:
    if not char:
        char = "-" if USE_ASCII else "─"
    return char * width


def _fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.2f} MB"
    if n >= 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n} B"


def _ok(flag: bool | None) -> str:
    if flag is None:
        return "SKIP"
    return "PASS" if flag else "FAIL"


def analyze(path: str, *, verify: bool = True, list_n: int = 0,
            explain: bool = False, as_json: bool = False) -> int:
    try:
        arc, data = zipfmt.load(path)
    except (OSError, zipfmt.ZipFormatError) as exc:
        print(f"error: 无法解析 {path}: {exc}", file=sys.stderr)
        return 2

    dex_files: list[dexfmt.DexFile] = []
    dex_errors: list[str] = []

    for entry in arc.dex_entries:
        try:
            blob = zipfmt.read_entry(data, entry)
            dex_files.append(dexfmt.analyze(blob, name=entry.name, verify=verify))
        except (zipfmt.ZipFormatError, dexfmt.DexFormatError) as exc:
            dex_errors.append(f"{entry.name}: {exc}")

    explained = {}
    if explain:
        for entry in arc.dex_entries:
            blob = zipfmt.read_entry(data, entry)
            header = dexfmt.parse_header(blob, entry.name)
            explained[entry.name] = dexfmt.explain_checksum(blob, header.checksum_stored)

    failed = (
        any(d.checksum_ok is False or d.signature_ok is False for d in dex_files)
        or bool(dex_errors)
        or bool(zipfmt.duplicate_names(arc))
    )

    if as_json:
        payload = {
            "path": path,
            "size": arc.size,
            "size_human": _fmt_size(arc.size),
            "entry_count": len(arc.entries),
            "zip64": arc.zip64,
            "comment": arc.comment,
            "apk_sig_block": {
                "present": arc.has_apk_sig_block,
                "offset": arc.apk_sig_block_offset,
                "size": arc.apk_sig_block_size,
            },
            "duplicate_names": zipfmt.duplicate_names(arc),
            "dex": [
                {
                    "name": d.name,
                    "size": d.size,
                    "version": d.header.version,
                    "checksum_stored": f"{d.header.checksum_stored:08x}",
                    "checksum_computed": (
                        f"{d.checksum_computed:08x}" if d.checksum_computed is not None else None
                    ),
                    "checksum_ok": d.checksum_ok,
                    "signature_ok": d.signature_ok,
                    "map_items": len(d.map_items),
                    "code_item_offset": d.code_item.offset if d.code_item else None,
                    "code_item_size": d.code_item.size if d.code_item else None,
                    "structural_errors": d.structural_errors,
                }
                for d in dex_files
            ],
            "dex_errors": dex_errors,
            "explain_checksum": explained,
            "integrity_ok": not failed,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 1 if failed else 0

    # ---- 文本报告 ----
    print(_hr("="))
    print(f"APK         : {path}")
    print(f"大小        : {_fmt_size(arc.size)}  ({arc.size} 字节)")
    print(f"归档条目    : {len(arc.entries)}")
    print(f"EOCD 偏移   : {arc.eocd_offset}")
    print(f"中央目录    : 偏移 {arc.cd_offset}, 大小 {_fmt_size(arc.cd_size)}")
    print(f"ZIP64       : {'是' if arc.zip64 else '否'}")
    if arc.comment:
        print(f"归档注释    : {arc.comment!r}")

    sig = "存在（v2/v3 签名块）" if arc.has_apk_sig_block else "未检出 v2/v3 签名块"
    print(f"APK 签名块  : {sig}")
    if arc.has_apk_sig_block:
        print(f"              偏移 {arc.apk_sig_block_offset}, 大小 {_fmt_size(arc.apk_sig_block_size)}")

    dupes = zipfmt.duplicate_names(arc)
    if dupes:
        print(f"{_mark('warn')} 重名条目  : {len(dupes)} 组 —— 归档可能被注入或错误重打包")
        for name, idxs in list(dupes.items())[:5]:
            print(f"              {name}  条目序号 {idxs}")

    # v1 签名文件
    v1 = [e.name for e in arc.entries if e.name.upper().startswith("META-INF/")
          and e.name.upper().endswith((".RSA", ".DSA", ".EC", ".SF"))]
    mf = arc.find("META-INF/MANIFEST.MF")
    if v1 or mf:
        print(f"v1 签名文件 : {len(v1)} 个签名文件{', 含 MANIFEST.MF' if mf else ''}")
        for n in v1:
            print(f"              {n}")

    # ---- DEX ----
    print()
    print(_hr("="))
    print(f"DEX 文件（{len(dex_files)} 个）")
    print(_hr("="))
    if not dex_files and not dex_errors:
        print("  （归档内未找到 classes*.dex）")

    for d in dex_files:
        h = d.header
        mark = _mark("ok") if d.is_valid else _mark("fail")
        ver = f"   DEX {h.version:03d}" if h.version >= 0 else ""
        print(f"\n  {mark} {d.name}   {_fmt_size(d.size)}{ver}")
        print(f"      magic        : {h.magic!r}")
        print(f"      file_size    : {h.file_size}  (实际 {d.size})")
        print(f"      endian_tag   : 0x{h.endian_tag:08x}")
        print(f"      checksum     : 记录 0x{h.checksum_stored:08x}"
              f"  实算 0x{(d.checksum_computed or 0):08x}   [{_ok(d.checksum_ok)}]")
        print(f"      signature    : {h.signature_stored.hex()[:24]}…   [{_ok(d.signature_ok)}]")
        print(f"      映射段数     : {len(d.map_items)}")
        for key, label in (
            ("string_ids_size", "字符串"), ("type_ids_size", "类型"),
            ("proto_ids_size", "原型"), ("method_ids_size", "方法"),
            ("field_ids_size", "字段"), ("class_defs_size", "类"),
        ):
            print(f"        {label:<6} : {getattr(h, key)}")
        ci = d.code_item
        if ci:
            print(f"      code_item    : 偏移 {ci.offset}, 共 {ci.size} 项  "
                  f"← 字节码主体，重打包改动的就是这里")
        for err in d.structural_errors:
            print(f"      {_mark('warn')} 结构问题   : {err}")

    for err in dex_errors:
        print(f"\n  {_mark('fail')} {err}")

    # ---- 校验和深度诊断 ----
    if explained:
        print()
        print(_hr("="))
        print("校验和诊断（DEX 规范：Adler-32 范围 data[12:]，模数 65521）")
        print(_hr("="))
        for name, info in explained.items():
            print(f"\n  {name}")
            print(f"      覆盖字节数        : {info['covered_bytes']}")
            print(f"      头部记录值        : 0x{info['stored']:08x}")
            print(f"      规范值(模 65521)  : 0x{info['correct_mod65521']:08x}"
                  f"   {'匹 配' if info['correct_matches_stored'] else '不匹配'}")
            print(f"      错误值(模 65536)  : 0x{info['wrong_mod65536']:08x}"
                  f"   {'匹配（说明写入方用错了模数！）' if info['wrong_mod65536_matches_stored'] else '不匹配'}")

    # ---- 条目列表 ----
    if list_n:
        print()
        print(_hr("="))
        print(f"归档条目（前 {min(list_n, len(arc.entries))} / {len(arc.entries)}）")
        print(_hr("="))
        print(f"  {'#':>4}  {'压缩':<8} {'原始':>10} {'压缩后':>10}  {'数据偏移':>10}  名称")
        for e in arc.entries[:list_n]:
            print(f"  {e.index:>4}  {e.method_name:<8} {e.uncomp_size:>10} "
                  f"{e.comp_size:>10}  {e.data_offset:>10}  {e.name}")

    print()
    print(_hr("="))
    if failed:
        print(f"结论: {_mark('fail')} 完整性校验未全部通过（见上方 FAIL 项）")
    else:
        print(f"结论: {_mark('ok')} 归档结构完整，所有 DEX 校验和与签名均匹配")
    print(_hr("="))
    return 1 if failed else 0


def render_compare(result, *, list_n: int = 30) -> None:
    """渲染双包差异比对报告。"""
    print()
    print(_hr("="))
    print("双包差异比对（验证「最小改动重打包」）")
    print(_hr("="))
    print(f"  A(基准) : {result.a_path}   {result.a_entries} 个条目")
    print(f"  B(对照) : {result.b_path}   {result.b_entries} 个条目")
    print()
    print(f"  字节级一致 : {len(result.identical)}")
    print(f"  内容有变化 : {len(result.changed)}")
    print(f"  仅 B 有    : {len(result.added)}")
    print(f"  仅 A 有    : {len(result.removed)}")
    print()

    if result.changed:
        print(f"  ── 内容发生变化的条目（最多显示 {list_n} 个）──")
        for d in result.changed[:list_n]:
            print(f"    {_mark('warn')} {d.name}")
            if d.detail:
                print(f"        {d.detail}")
            if d.sha_a:
                print(f"        SHA-256 {d.sha_a} → {d.sha_b}")
        print()

    for label, items in (("仅 B 新增", result.added), ("仅 A 存在", result.removed)):
        if items:
            print(f"  ── {label}的条目（最多显示 {list_n} 个）──")
            for d in items[:list_n]:
                print(f"      {d.name}")
            print()

    pct = (len(result.identical) / result.a_entries * 100) if result.a_entries else 0.0
    verdict = _mark("ok") if result.minimal else _mark("fail")
    print(f"  结论: {verdict} {len(result.identical)}/{result.a_entries} 个条目字节级未变"
          f"（{pct:.2f}%）")
    if result.minimal:
        print("        改动高度集中，符合「最小改动重打包」预期")
    else:
        print("        改动面过大——打包器很可能重写了不该动的条目")
        print("        （典型原因：整包重压缩、丢失 extra 字段、条目顺序被重排）")
    print(_hr("="))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="apk-analyzer",
        description="Android APK / DEX 结构分析器（零第三方依赖，手写格式解析）",
    )
    ap.add_argument("apk", help="待分析的 .apk 文件")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--no-verify", action="store_true",
                    help="跳过 Adler-32 / SHA-1 实算（大文件可加速）")
    ap.add_argument("--list", type=int, default=0, metavar="N",
                    help="列出前 N 个归档条目")
    ap.add_argument("--explain-checksum", action="store_true",
                    help="对每个 dex 输出校验和诊断（含错误模数对照）")
    ap.add_argument("--ascii", action="store_true",
                    help="纯 ASCII 输出（控制台不支持 UTF-8 时使用）")
    ap.add_argument("--compare", metavar="OTHER_APK", default=None,
                    help="与另一个 APK 逐条目比对（验证最小改动重打包）")
    ap.add_argument("--deep", action="store_true",
                    help="与 --compare 同用时，额外解压比对 SHA-256（更慢但绝对严格）")
    ap.add_argument("--diff-limit", type=int, default=30, metavar="N",
                    help="差异清单最多显示 N 条（默认 30）")
    args = ap.parse_args(argv)

    global USE_ASCII
    USE_ASCII = args.ascii
    setup_console()

    path = str(Path(args.apk))
    code = analyze(path, verify=not args.no_verify, list_n=args.list,
                   explain=args.explain_checksum, as_json=args.json)

    if args.compare and not args.json:
        try:
            result = compare_mod.compare(path, str(Path(args.compare)), deep=args.deep)
        except (OSError, zipfmt.ZipFormatError) as exc:
            print(f"error: 比对失败: {exc}", file=sys.stderr)
            return 2
        render_compare(result, list_n=args.diff_limit)
        if not result.minimal:
            code = 1
    elif args.compare and args.json:
        try:
            result = compare_mod.compare(path, str(Path(args.compare)), deep=args.deep)
        except (OSError, zipfmt.ZipFormatError) as exc:
            print(f"error: 比对失败: {exc}", file=sys.stderr)
            return 2
        print(json.dumps({
            "a": result.a_path,
            "b": result.b_path,
            "a_entries": result.a_entries,
            "b_entries": result.b_entries,
            "identical": len(result.identical),
            "changed": [{"name": d.name, "detail": d.detail} for d in result.changed],
            "added": [d.name for d in result.added],
            "removed": [d.name for d in result.removed],
            "minimal_change": result.minimal,
        }, ensure_ascii=False, indent=2))

    return code


if __name__ == "__main__":
    raise SystemExit(main())
