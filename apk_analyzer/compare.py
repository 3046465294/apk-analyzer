"""
compare — 两个 APK 的逐条目差异比对。

用途：验证「最小改动重打包」是否真的做到了最小。
一个正确的 APK 重打包应当只动少数几个条目，其余条目保持字节级一致；
如果几百个条目的 CRC 都变了，说明打包器改写了你不想动的东西
（常见于用 zip 工具重新压缩、丢失 extra 字段、或改变了条目顺序）。

判定依据：
    ZIP 条目记录了 CRC-32 + 压缩后大小 + 原始大小 + 压缩方法。
    四者全部相同，即可认定内容字节一致
    （CRC-32 碰撞在 18MB 量级上可忽略，且还有两个长度字段交叉约束）。
    如需绝对严格，加 --deep 会实际解压并比对 SHA-256。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from . import zipfmt

IDENTICAL = "identical"
CHANGED = "changed"
ADDED = "added"
REMOVED = "removed"


@dataclass
class EntryDiff:
    name: str
    status: str
    detail: str = ""
    sha_a: str = ""
    sha_b: str = ""


@dataclass
class CompareResult:
    a_path: str
    b_path: str
    a_entries: int = 0
    b_entries: int = 0
    diffs: list[EntryDiff] = field(default_factory=list)

    @property
    def identical(self) -> list[EntryDiff]:
        return [d for d in self.diffs if d.status == IDENTICAL]

    @property
    def changed(self) -> list[EntryDiff]:
        return [d for d in self.diffs if d.status == CHANGED]

    @property
    def added(self) -> list[EntryDiff]:
        return [d for d in self.diffs if d.status == ADDED]

    @property
    def removed(self) -> list[EntryDiff]:
        return [d for d in self.diffs if d.status == REMOVED]

    @property
    def minimal(self) -> bool:
        """
        改动是否「最小」。

        判定要同时看绝对量和占比，只看其中一个都会出错：
        - 只看绝对量：5 个条目的归档改了 5 个也会被判为最小（全部重写！）
        - 只看占比：真正的大包只改 1 个条目时占比极小，看似没问题，
          但也可能掩盖「改了 20 个」这种不该放过的情况

        因此规则是：改动数严格少于总条目数，且满足
        「不超过 2 个」或「占比不超过 2%」。
        """
        total = self.a_entries
        if total == 0:
            return False
        changed = len(self.changed)
        if changed >= total:
            return False
        return changed <= 2 or (changed / total) <= 0.02


def _identity(entry: zipfmt.ZipEntry) -> tuple:
    """条目的内容指纹（无需解压即可判定字节一致）。"""
    return (entry.method, entry.crc32, entry.comp_size, entry.uncomp_size)


def compare(
    a_path: str,
    b_path: str,
    *,
    deep: bool = False,
) -> CompareResult:
    arc_a, data_a = zipfmt.load(a_path)
    arc_b, data_b = zipfmt.load(b_path)

    result = CompareResult(a_path=a_path, b_path=b_path,
                           a_entries=len(arc_a.entries), b_entries=len(arc_b.entries))

    map_a = {e.name: e for e in arc_a.entries}
    map_b = {e.name: e for e in arc_b.entries}

    def sha(data: bytes, entry: zipfmt.ZipEntry) -> str:
        try:
            return hashlib.sha256(zipfmt.read_entry(data, entry)).hexdigest()[:16]
        except zipfmt.ZipFormatError:
            return "<解压失败>"

    for name in map_a:
        ea = map_a[name]
        eb = map_b.get(name)
        if eb is None:
            result.diffs.append(EntryDiff(name, REMOVED))
            continue

        if _identity(ea) == _identity(eb):
            d = EntryDiff(name, IDENTICAL)
            if deep:
                d.sha_a = sha(data_a, ea)
                d.sha_b = sha(data_b, eb)
                if d.sha_a != d.sha_b:
                    d.status = CHANGED
                    d.detail = "CRC/长度相同但解压内容不同（异常）"
            result.diffs.append(d)
        else:
            parts = []
            if ea.crc32 != eb.crc32:
                parts.append(f"CRC 0x{ea.crc32:08x}→0x{eb.crc32:08x}")
            if ea.comp_size != eb.comp_size:
                parts.append(f"压缩后 {ea.comp_size}→{eb.comp_size}")
            if ea.uncomp_size != eb.uncomp_size:
                parts.append(f"原始 {ea.uncomp_size}→{eb.uncomp_size}")
            if ea.method != eb.method:
                parts.append(f"压缩方式 {ea.method_name}→{eb.method_name}")
            d = EntryDiff(name, CHANGED, "; ".join(parts))
            if deep:
                d.sha_a = sha(data_a, ea)
                d.sha_b = sha(data_b, eb)
            result.diffs.append(d)

    for name in map_b:
        if name not in map_a:
            result.diffs.append(EntryDiff(name, ADDED))

    return result
