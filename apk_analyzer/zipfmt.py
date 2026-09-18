"""
zipfmt — 手写 ZIP / APK 归档格式解析器。

为什么不用标准库 zipfile？
    因为本项目的价值就在于「按格式规范自己解析字节」。
    zipfile 会把 EOCD -> 中央目录 -> 本地头 -> 数据偏移 这条链路全部隐藏，
    而这些恰恰是排查 APK 问题时真正需要看的东西。
    另外 zipfile 不会告诉你 extra 字段长度、数据描述符标志、条目顺序——
    而 APK 的最小改动重打包恰恰依赖这三样东西。

正确性由 tests/ 与标准库 zipfile 交叉验证（见 tests/test_zipfmt.py）。

参考：PKWARE APPNOTE.TXT 6.3.x（4.3.6 本地文件头 / 4.3.12 中央目录 / 4.3.16 EOCD）
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field

# ---- 结构签名（小端 u32）----------------------------------------------------
LFH_SIG = 0x04034B50        # 本地文件头
CDFH_SIG = 0x02014B50       # 中央目录文件头
EOCD_SIG = 0x06054B50       # 中央目录结束记录
ZIP64_EOCD_SIG = 0x06064B50  # ZIP64 结束记录
ZIP64_LOC_SIG = 0x07064B50   # ZIP64 结束记录定位器
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"   # APK Signing Block（v2/v3）魔术字节

# 压缩方法编号 -> 名称
METHOD_NAMES = {
    0: "stored",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    99: "aes",
}

# 通用位标志
FLAG_ENCRYPTED = 1 << 0
FLAG_DATA_DESCRIPTOR = 1 << 3
FLAG_UTF8_NAME = 1 << 11


class ZipFormatError(Exception):
    """归档结构不符合规范时抛出。"""


@dataclass
class ZipEntry:
    """一个中央目录条目（含由本地头推导出的数据偏移）。"""

    name: str
    method: int
    flags: int
    crc32: int
    comp_size: int
    uncomp_size: int
    local_header_offset: int
    extra_len: int
    comment: str
    index: int

    # 由本地文件头推导（解析后填充）
    local_header_size: int = 0
    data_offset: int = 0

    @property
    def method_name(self) -> str:
        return METHOD_NAMES.get(self.method, f"unknown({self.method})")

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def has_data_descriptor(self) -> bool:
        return bool(self.flags & FLAG_DATA_DESCRIPTOR)

    @property
    def name_is_utf8(self) -> bool:
        return bool(self.flags & FLAG_UTF8_NAME)


@dataclass
class ZipArchive:
    """整个归档的解析结果。"""

    path: str
    size: int
    entries: list[ZipEntry] = field(default_factory=list)
    comment: str = ""
    cd_offset: int = 0
    cd_size: int = 0
    eocd_offset: int = 0
    zip64: bool = False

    # APK 特有
    has_apk_sig_block: bool = False
    apk_sig_block_offset: int = 0
    apk_sig_block_size: int = 0

    def find(self, name: str) -> ZipEntry | None:
        for e in self.entries:
            if e.name == name:
                return e
        return None

    def glob(self, suffix: str) -> list[ZipEntry]:
        return [e for e in self.entries if e.name.endswith(suffix)]

    @property
    def dex_entries(self) -> list[ZipEntry]:
        """classes.dex / classes2.dex / ... 按 DEX 序号排序。"""
        out = []
        for e in self.entries:
            base = e.name.rsplit("/", 1)[-1]
            if base == "classes.dex" or (base.startswith("classes") and base.endswith(".dex")):
                out.append(e)

        def dex_order(entry: ZipEntry) -> int:
            base = entry.name.rsplit("/", 1)[-1]
            if base == "classes.dex":
                return 1
            digits = base[len("classes"):-len(".dex")]
            return int(digits) if digits.isdigit() else 9999

        return sorted(out, key=dex_order)


def find_eocd(data: bytes) -> int:
    """
    从文件尾部向前搜索 EOCD 签名。

    EOCD 后面最多跟 65535 字节的归档注释，所以最多回扫 65535+22 字节。
    """
    max_comment = 0xFFFF
    start = max(0, len(data) - (max_comment + 22))
    for i in range(len(data) - 22, start - 1, -1):
        if data[i] == 0x50 and data[i:i + 4] == struct.pack("<I", EOCD_SIG):
            return i
    raise ZipFormatError("未找到 EOCD（中央目录结束记录）——不是有效的 ZIP/APK 文件")


def _decode_name(raw: bytes, is_utf8: bool) -> str:
    if is_utf8:
        return raw.decode("utf-8", errors="replace")
    # 未置 UTF-8 标志时规范上是 CP437；实际中文 APK 里常见 GBK，做兜底
    try:
        return raw.decode("cp437")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


def parse(data: bytes, path: str = "<bytes>") -> ZipArchive:
    """解析 ZIP/APK 字节流。"""
    arc = ZipArchive(path=path, size=len(data))

    eocd_off = find_eocd(data)
    arc.eocd_offset = eocd_off

    (
        _sig, _disk, _cd_disk, _n_this, n_total,
        cd_size, cd_offset, comment_len,
    ) = struct.unpack_from("<IHHHHIIH", data, eocd_off)

    arc.cd_offset = cd_offset
    arc.cd_size = cd_size
    if comment_len:
        arc.comment = data[eocd_off + 22:eocd_off + 22 + comment_len].decode(
            "utf-8", errors="replace"
        )

    # ZIP64 探测：EOCD 之前的 20 字节若有定位器，说明是 ZIP64
    loc_off = eocd_off - 20
    if loc_off >= 0 and struct.unpack_from("<I", data, loc_off)[0] == ZIP64_LOC_SIG:
        arc.zip64 = True
        zip64_eocd_off = struct.unpack_from("<Q", data, loc_off + 8)[0]
        if struct.unpack_from("<I", data, zip64_eocd_off)[0] == ZIP64_EOCD_SIG:
            n_total = struct.unpack_from("<Q", data, zip64_eocd_off + 32)[0]
            cd_size, cd_offset = struct.unpack_from("<QQ", data, zip64_eocd_off + 40)
            arc.cd_offset, arc.cd_size = cd_offset, cd_size

    # ---- 中央目录 ----
    pos = cd_offset
    for idx in range(n_total):
        if struct.unpack_from("<I", data, pos)[0] != CDFH_SIG:
            raise ZipFormatError(
                f"中央目录第 {idx} 项签名错误（偏移 {pos}），归档可能被截断或损坏"
            )
        (
            _ver_made, _ver_need, flags, method, _mt, _md, crc, comp, unc,
            name_len, extra_len, cmt_len, _disk_start, _int_attr, _ext_attr,
            lho,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", data, pos + 4)

        name_off = pos + 46
        raw_name = data[name_off:name_off + name_len]
        entry = ZipEntry(
            name=_decode_name(raw_name, bool(flags & FLAG_UTF8_NAME)),
            method=method,
            flags=flags,
            crc32=crc,
            comp_size=comp,
            uncomp_size=unc,
            local_header_offset=lho,
            extra_len=extra_len,
            comment=data[name_off + name_len + extra_len:
                         name_off + name_len + extra_len + cmt_len].decode(
                             "utf-8", errors="replace"),
            index=idx,
        )
        arc.entries.append(entry)
        pos = name_off + name_len + extra_len + cmt_len

    # ---- 由本地文件头推导每个条目的数据偏移 ----
    for e in arc.entries:
        lho = e.local_header_offset
        if struct.unpack_from("<I", data, lho)[0] != LFH_SIG:
            raise ZipFormatError(f"条目 {e.name!r} 的本地文件头签名错误（偏移 {lho}）")
        l_name_len, l_extra_len = struct.unpack_from("<HH", data, lho + 26)
        e.local_header_size = 30 + l_name_len + l_extra_len
        e.data_offset = lho + e.local_header_size

    # ---- APK Signing Block（v2/v3）探测 ----
    # 结构：[u64 block_size][id-value pairs...][u64 block_size]["APK Sig Block 42"]
    # 它紧贴在中央目录之前。
    magic_off = cd_offset - 16
    if magic_off >= 0 and data[magic_off:magic_off + 16] == APK_SIG_BLOCK_MAGIC:
        block_size_trailer = struct.unpack_from("<Q", data, magic_off - 8)[0]
        arc.has_apk_sig_block = True
        arc.apk_sig_block_size = block_size_trailer + 8
        arc.apk_sig_block_offset = cd_offset - arc.apk_sig_block_size

    return arc


def read_entry(data: bytes, entry: ZipEntry, *, verify_crc: bool = True) -> bytes:
    """读取并解压一个条目的内容。"""
    if entry.encrypted:
        raise ZipFormatError(f"条目 {entry.name!r} 已加密，本工具不支持解密")
    raw = data[entry.data_offset:entry.data_offset + entry.comp_size]
    if len(raw) != entry.comp_size:
        raise ZipFormatError(f"条目 {entry.name!r} 数据被截断")

    if entry.method == 0:
        out = raw
    elif entry.method == 8:
        out = zlib.decompress(raw, -zlib.MAX_WBITS)
    else:
        raise ZipFormatError(
            f"条目 {entry.name!r} 使用了不支持的压缩方法 {entry.method_name}"
        )

    if verify_crc:
        actual = zlib.crc32(out) & 0xFFFFFFFF
        if actual != entry.crc32:
            raise ZipFormatError(
                f"条目 {entry.name!r} CRC32 校验失败："
                f"记录 0x{entry.crc32:08x}，实算 0x{actual:08x}"
            )
    return out


def load(path: str) -> tuple[ZipArchive, bytes]:
    """读取文件并解析。返回 (归档对象, 原始字节)。"""
    with open(path, "rb") as fh:
        data = fh.read()
    return parse(data, path=path), data


def duplicate_names(arc: ZipArchive) -> dict[str, list[int]]:
    """找出重名条目——这是「APK 注入」类异常和错误重打包的常见特征。"""
    seen: dict[str, list[int]] = {}
    for e in arc.entries:
        seen.setdefault(e.name, []).append(e.index)
    return {k: v for k, v in seen.items() if len(v) > 1}
