"""
dexfmt — 手写 DEX（Dalvik Executable）文件格式解析与完整性验证。

这是本项目的核心模块。DEX 头部的两个校验字段是「重打包能不能跑起来」的
关键，也是绝大多数自制工具翻车的地方：

    checksum  = Adler-32，范围 data[12:]，模数必须是 **65521**
    signature = SHA-1，  范围 data[32:]

为什么特别强调模数 65521？
    Adler-32 的定义里 B 累加和对 65521（小于 2^16 的最大质数）取模。
    实现时很容易写成 65536（2^16，因为 A/B 都是 u16 就顺手写成 65536），
    两者结果不同，而 ART 启动时会严格比对——校验不符就直接拒绝加载整个 dex，
    表现为 ClassNotFoundException，且报错信息完全指不到真正的原因。

本模块同时提供 compute_adler32_mod() ，可显式用任意模数计算，
用来演示「错误模数」与规范值产生的差异（见 --explain-checksum）。

参考：Android 源码 dalvik/libdex/DexFile.h（struct DexHeader / DexMapItem）
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

DEX_MAGIC_PREFIX = b"dex\n"
DEX_MAGIC_SUFFIX = b"\x00"
DEX_HEADER_SIZE = 0x70  # 112 字节，即以下所有字段之和

# endian_tag 常量
ENDIAN_CONSTANT = 0x12345678
REVERSE_ENDIAN_CONSTANT = 0x78563412

# Adler-32 规范模数：小于 2^16 的最大质数。
ADLER_MODULUS = 65521
# 常见错误：把 u16 的进位模数 2^16 当成 Adler-32 的模数。
ADLER_WRONG_MODULUS = 65536

# DexMapItem 的 type 编码 -> 名称
MAP_TYPE_NAMES = {
    0x0000: "header_item",
    0x0001: "string_id_item",
    0x0002: "type_id_item",
    0x0003: "proto_id_item",
    0x0004: "field_id_item",
    0x0005: "method_id_item",
    0x0006: "class_def_item",
    0x1000: "map_list",
    0x1001: "type_list",
    0x1002: "annotation_set_ref_list",
    0x1003: "annotation_set_item",
    0x2000: "class_data_item",
    0x2001: "code_item",
    0x2002: "string_data_item",
    0x2003: "debug_info_item",
    0x2004: "annotation_item",
    0x2005: "encoded_array_item",
    0x2006: "annotations_directory_item",
    0x2007: "hiddenapi_class_data_item",
}


class DexFormatError(Exception):
    """DEX 结构不符合规范时抛出。"""


def adler32_mod(data: bytes, modulus: int = ADLER_MODULUS) -> int:
    """
    按给定模数计算 Adler-32。

    modulus=65521 为 DEX 规范要求；传 65536 可复现常见的错误实现。

    实现说明：逐字节取模与「先精确累加、最后统一取模」在数学上等价——
    a 的每一步精确值都同余于其模值，而 b 是这些值的和，加法保持同余。
    Python 大整数不会溢出，所以这里把取模推迟到循环外，
    省掉上百万次 `%` 运算（对 7MB 的 dex 是数量级的差别）。
    """
    a = 1
    b = 0
    for byte in data:
        a += byte
        b += a
    return (((b % modulus) << 16) | (a % modulus)) & 0xFFFFFFFF


@dataclass
class MapItem:
    type_code: int
    size: int
    offset: int

    @property
    def type_name(self) -> str:
        return MAP_TYPE_NAMES.get(self.type_code, f"unknown(0x{self.type_code:04x})")


@dataclass
class DexHeader:
    magic: bytes
    version: int
    checksum_stored: int
    signature_stored: bytes
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int


@dataclass
class DexFile:
    name: str
    size: int
    header: DexHeader
    map_items: list[MapItem] = field(default_factory=list)

    # 验证结果
    checksum_computed: int | None = None
    checksum_ok: bool | None = None
    signature_computed: bytes | None = None
    signature_ok: bool | None = None
    structural_errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return (
            self.checksum_ok is True
            and self.signature_ok is True
            and not self.structural_errors
        )

    @property
    def code_item(self) -> MapItem | None:
        """code_item（字节码主体）在文件中的位置——重打包改动的就是它。"""
        for item in self.map_items:
            if item.type_code == 0x2001:
                return item
        return None


def parse_header(data: bytes, name: str = "<dex>") -> DexHeader:
    if len(data) < DEX_HEADER_SIZE:
        raise DexFormatError(
            f"{name}: 文件只有 {len(data)} 字节，不足 DEX 头部所需的 {DEX_HEADER_SIZE} 字节"
        )
    magic = data[0:8]
    if not magic.startswith(DEX_MAGIC_PREFIX):
        raise DexFormatError(
            f"{name}: magic 不是 'dex\\n'（实际为 {magic!r}）——不是 DEX 文件"
        )

    try:
        version = int(magic[4:7])
    except ValueError:
        version = -1

    fields = struct.unpack_from("<I20s20I", data, 8)
    checksum_stored = fields[0]
    signature_stored = fields[1]
    rest = fields[2:]

    return DexHeader(
        magic=magic,
        version=version,
        checksum_stored=checksum_stored,
        signature_stored=signature_stored,
        file_size=rest[0],
        header_size=rest[1],
        endian_tag=rest[2],
        link_size=rest[3],
        link_off=rest[4],
        map_off=rest[5],
        string_ids_size=rest[6],
        string_ids_off=rest[7],
        type_ids_size=rest[8],
        type_ids_off=rest[9],
        proto_ids_size=rest[10],
        proto_ids_off=rest[11],
        field_ids_size=rest[12],
        field_ids_off=rest[13],
        method_ids_size=rest[14],
        method_ids_off=rest[15],
        class_defs_size=rest[16],
        class_defs_off=rest[17],
        data_size=rest[18],
        data_off=rest[19],
    )


def parse_map(data: bytes, map_off: int) -> list[MapItem]:
    """解析 map_list：DEX 内所有段的类型/数量/偏移目录。"""
    if map_off == 0 or map_off + 4 > len(data):
        return []
    count = struct.unpack_from("<I", data, map_off)[0]
    items = []
    pos = map_off + 4
    for _ in range(count):
        if pos + 12 > len(data):
            break
        type_code, _unused, size, offset = struct.unpack_from("<HHII", data, pos)
        items.append(MapItem(type_code=type_code, size=size, offset=offset))
        pos += 12
    return items


def analyze(data: bytes, name: str = "<dex>", *, verify: bool = True) -> DexFile:
    """
    解析一个 DEX 并验证完整性。

    verify=True 时会实算 Adler-32 与 SHA-1，与头部记录值比对。
    注意：对几十 MB 的文件逐字节算 Adler-32 是纯 Python 循环，较慢；
    正常调用请用 verify_checksum_fast()（走 zlib 的 C 实现）。
    """
    header = parse_header(data, name)

    dex = DexFile(name=name, size=len(data), header=header)
    dex.map_items = parse_map(data, header.map_off)

    # 结构一致性检查
    if header.file_size != len(data):
        dex.structural_errors.append(
            f"头部 file_size={header.file_size} 与实际长度 {len(data)} 不一致"
        )
    if header.header_size != DEX_HEADER_SIZE:
        dex.structural_errors.append(
            f"header_size={header.header_size}，规范值为 {DEX_HEADER_SIZE}"
        )
    if header.endian_tag not in (ENDIAN_CONSTANT, REVERSE_ENDIAN_CONSTANT):
        dex.structural_errors.append(
            f"endian_tag=0x{header.endian_tag:08x} 既不是 ENDIAN_CONSTANT 也不是 REVERSE_ENDIAN_CONSTANT"
        )
    elif header.endian_tag == REVERSE_ENDIAN_CONSTANT:
        dex.structural_errors.append("该 DEX 为大端序（reverse endian），本工具按小端解析，结果可能不准")

    if verify:
        dex.signature_computed = hashlib.sha1(data[32:]).digest()
        dex.signature_ok = dex.signature_computed == header.signature_stored
        dex.checksum_computed = verify_checksum(data, header.checksum_stored)
        dex.checksum_ok = dex.checksum_computed == header.checksum_stored

    return dex


def verify_checksum(data: bytes, stored: int) -> int:
    """
    计算 DEX 规范的 Adler-32（范围 data[12:]），返回实算值。

    这里用 zlib.adler32（C 实现）以保证大文件速度；它与规范定义完全一致，
    该等价性由 tests/test_dexfmt.py 用纯 Python 的 adler32_mod() 交叉验证。
    """
    return zlib.adler32(data[12:]) & 0xFFFFFFFF


def explain_checksum(data: bytes, stored: int) -> dict[str, object]:
    """
    诊断辅助：同时给出规范值、错误模数下的值、以及头部记录值。

    用来把「Adler-32 用错模数」这类问题显式暴露出来——
    只看 ART 的报错信息是永远定位不到这一层的。
    """
    correct = zlib.adler32(data[12:]) & 0xFFFFFFFF
    wrong = adler32_mod(data[12:], ADLER_WRONG_MODULUS)
    return {
        "stored": stored,
        "correct_mod65521": correct,
        "wrong_mod65536": wrong,
        "correct_matches_stored": correct == stored,
        "wrong_mod65536_matches_stored": wrong == stored,
        "covered_bytes": len(data) - 12,
    }
