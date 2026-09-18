"""
zipfmt 自测。

核心思路：本模块是「手写」ZIP 解析，所以它的正确性必须由外部标准来锚定——
这里用标准库 zipfile 作为参照实现，逐字段交叉验证。
这比「我自己跑通了没报错」强得多：它能证明手写解析与成熟实现在字节层面一致。

运行：
    python -m unittest discover -s tests -v
"""

import io
import random
import struct
import unittest
import zipfile
import zlib

from apk_analyzer import zipfmt


def build_zip(payloads: dict[str, bytes], compress: bool = True) -> bytes:
    """用标准库造一个 ZIP 作为参照物。"""
    buf = io.BytesIO()
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(buf, "w", mode) as zf:
        for name, data in payloads.items():
            zf.writestr(name, data)
    return buf.getvalue()


def with_fake_apk_sig_block(blob: bytes) -> bytes:
    """
    在中央目录之前插入一个合成的 APK Signing Block，并修正 EOCD 的 cd_offset/cd_size。

    结构：[u64 block_size][id-value][u64 block_size]["APK Sig Block 42"]
    用来测试签名块探测逻辑，不需要真实的签名数据。
    """
    eocd_off = zipfmt.find_eocd(blob)
    _sig, _d, _cd, _n, _nt, cd_size, cd_offset, cmt_len = struct.unpack_from(
        "<IHHHHIIH", blob, eocd_off
    )

    magic = zipfmt.APK_SIG_BLOCK_MAGIC          # 16 字节，必须位于整块最后
    pair = struct.pack("<Q", 0x7109871A) + struct.pack("<I", 4) + b"\xde\xad\xbe\xef"
    # 真实布局：[u64 size][id-value pairs][u64 size][magic]
    # 其中 size = 整块长度 - 8（不含第一个 size 字段自身）
    block_size = len(pair) + 8 + len(magic)
    block = (struct.pack("<Q", block_size) + pair
             + struct.pack("<Q", block_size) + magic)

    new_blob = blob[:cd_offset] + block + blob[cd_offset:]
    new_cd_offset = cd_offset + len(block)
    new_eocd_off = eocd_off + len(block)

    patched = bytearray(new_blob)
    struct.pack_into("<I", patched, new_eocd_off + 12, cd_size)
    struct.pack_into("<I", patched, new_eocd_off + 16, new_cd_offset)
    return bytes(patched)


class TestZipParsing(unittest.TestCase):
    def setUp(self):
        random.seed(20260917)
        self.payloads = {
            "classes.dex": bytes(random.getrandbits(8) for _ in range(5000)),
            "classes2.dex": bytes(random.getrandbits(8) for _ in range(3000)),
            "res/values/strings.xml": b"<resources/>" * 50,
            "assets/data.bin": b"\x00\x01\x02" * 1000,
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
        }
        self.blob = build_zip(self.payloads)
        self.arc = zipfmt.parse(self.blob, "synthetic")

    # ---- 与标准库交叉验证 ----
    def test_entry_names_match_zipfile(self):
        with zipfile.ZipFile(io.BytesIO(self.blob)) as zf:
            self.assertEqual(sorted(e.name for e in self.arc.entries), sorted(zf.namelist()))

    def test_sizes_crc_and_method_match_zipfile(self):
        with zipfile.ZipFile(io.BytesIO(self.blob)) as zf:
            for info in zf.infolist():
                mine = self.arc.find(info.filename)
                self.assertIsNotNone(mine, f"缺少条目 {info.filename}")
                self.assertEqual(mine.crc32, info.CRC, f"{info.filename} CRC 不一致")
                self.assertEqual(mine.comp_size, info.compress_size,
                                 f"{info.filename} 压缩后大小不一致")
                self.assertEqual(mine.uncomp_size, info.file_size,
                                 f"{info.filename} 原始大小不一致")
                self.assertEqual(mine.method, info.compress_type,
                                 f"{info.filename} 压缩方法不一致")

    def test_data_offsets_are_correct(self):
        """
        最关键的断言：用自己算出的 data_offset 直接切原始字节并解压，
        结果必须与原始输入逐字节相同。data_offset 错一个字节这里就会红。
        """
        for name, expected in self.payloads.items():
            entry = self.arc.find(name)
            raw = self.blob[entry.data_offset:entry.data_offset + entry.comp_size]
            if entry.method == 0:
                got = raw
            else:
                got = zlib.decompress(raw, -zlib.MAX_WBITS)
            self.assertEqual(got, expected, f"{name} 按 data_offset 取出的内容与原文不符")

    def test_read_entry_roundtrip(self):
        for name, expected in self.payloads.items():
            got = zipfmt.read_entry(self.blob, self.arc.find(name))
            self.assertEqual(got, expected, f"{name} read_entry 往返失败")

    def test_stored_method_archive(self):
        blob = build_zip({"a.bin": b"x" * 100, "b.bin": b"y" * 10}, compress=False)
        arc = zipfmt.parse(blob)
        self.assertTrue(all(e.method == 0 for e in arc.entries))
        self.assertEqual(zipfmt.read_entry(blob, arc.find("a.bin")), b"x" * 100)

    # ---- 边界与错误路径 ----
    def test_non_zip_raises(self):
        with self.assertRaises(zipfmt.ZipFormatError):
            zipfmt.parse(b"this is definitely not a zip file" * 10)

    def test_crc_mismatch_is_detected(self):
        """
        破坏条目内容但不改任何头部记录 —— 读取时必须报 CRC 校验失败。

        用 stored（不压缩）方式造包，这样改一个数据字节不会破坏 deflate 流，
        能干净地落在 CRC 校验这条路径上。
        """
        blob = bytearray(build_zip({"assets/data.bin": b"ABCDEFGH" * 100},
                                   compress=False))
        arc = zipfmt.parse(bytes(blob), "stored")
        entry = arc.find("assets/data.bin")
        blob[entry.data_offset] ^= 0xFF          # 只改数据，CRC 记录保持原样
        with self.assertRaises(zipfmt.ZipFormatError):
            zipfmt.read_entry(bytes(blob), entry)

    def test_truncated_archive_raises(self):
        with self.assertRaises(zipfmt.ZipFormatError):
            zipfmt.parse(self.blob[:100])

    def test_dex_entries_ordering(self):
        arc = self.arc
        self.assertEqual([e.name for e in arc.dex_entries], ["classes.dex", "classes2.dex"])

    def test_duplicate_names_empty_for_clean_archive(self):
        self.assertEqual(zipfmt.duplicate_names(self.arc), {})

    # ---- APK Signing Block 探测 ----
    def test_apk_sig_block_absent_by_default(self):
        self.assertFalse(self.arc.has_apk_sig_block)

    def test_apk_sig_block_detected_when_present(self):
        blob = with_fake_apk_sig_block(self.blob)
        arc = zipfmt.parse(blob, "with-sig-block")
        self.assertTrue(arc.has_apk_sig_block, "合成的签名块未被识别")
        self.assertEqual(arc.entries and len(arc.entries), len(self.arc.entries))
        self.assertEqual(arc.apk_sig_block_offset + arc.apk_sig_block_size, arc.cd_offset,
                         "签名块区间应正好紧贴中央目录之前")


if __name__ == "__main__":
    unittest.main(verbosity=2)
