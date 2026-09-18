"""
dexfmt 自测。

两条主线：
1. 纯 Python 的 adler32_mod() 必须与 zlib.adler32（C 实现）逐值相等——
   这是「我的实现符合规范」的锚点。
2. 模数 65521 与 65536 必须产生不同结果——这是本项目要暴露的那个真实缺陷。

另外用合成 DEX 覆盖校验和/签名验证的正反两个方向。
"""

import hashlib
import random
import struct
import unittest
import zlib

from apk_analyzer import dexfmt


def make_dex(payload: bytes = b"\x00" * 64, *, version: int = 35) -> bytes:
    """构造一个头部完全合法的 DEX（无映射表，仅用于验证校验逻辑）。"""
    header = bytearray(112)
    header[0:8] = b"dex\n" + f"{version:03d}".encode() + b"\x00"

    total = 112 + len(payload)
    struct.pack_into("<I", header, 32, total)       # file_size
    struct.pack_into("<I", header, 36, 0x70)        # header_size
    struct.pack_into("<I", header, 40, 0x12345678)  # endian_tag
    # 其余段偏移/数量留 0，表示空 DEX

    data = bytes(header) + payload

    # 顺序不可颠倒：先写 SHA-1（偏移 32 起），再对更新后的 data[12:] 算 Adler-32
    sig = hashlib.sha1(data[32:]).digest()
    data = data[:12] + sig + data[32:]

    checksum = zlib.adler32(data[12:]) & 0xFFFFFFFF
    data = data[:8] + struct.pack("<I", checksum) + data[12:]
    return data


class TestAdler32(unittest.TestCase):
    def test_matches_zlib_for_random_data(self):
        """纯 Python 实现 vs zlib C 实现，多组随机数据逐值比对。"""
        random.seed(7)
        for size in (0, 1, 2, 17, 255, 1000, 4096, 20000):
            blob = bytes(random.getrandbits(8) for _ in range(size))
            self.assertEqual(
                dexfmt.adler32_mod(blob), zlib.adler32(blob) & 0xFFFFFFFF,
                f"长度 {size} 时纯 Python 实现与 zlib 不一致",
            )

    def test_matches_zlib_for_edge_patterns(self):
        for blob in (b"", b"\x00", b"\xff", b"\x00" * 1000, b"\xff" * 1000,
                     b"\x01\x02\x03\x04\x05"):
            self.assertEqual(dexfmt.adler32_mod(blob), zlib.adler32(blob) & 0xFFFFFFFF)

    def test_wrong_modulus_differs(self):
        """核心断言：用 65536 当模数会得到与规范不同的结果。"""
        random.seed(99)
        blob = bytes(random.getrandbits(8) for _ in range(3000))
        correct = dexfmt.adler32_mod(blob, dexfmt.ADLER_MODULUS)
        wrong = dexfmt.adler32_mod(blob, dexfmt.ADLER_WRONG_MODULUS)
        self.assertNotEqual(correct, wrong,
                            "模数 65521 与 65536 应当产生不同校验值")
        self.assertEqual(correct, zlib.adler32(blob) & 0xFFFFFFFF)

    def test_modulus_constants(self):
        self.assertEqual(dexfmt.ADLER_MODULUS, 65521)
        self.assertEqual(dexfmt.ADLER_WRONG_MODULUS, 65536)
        self.assertTrue(dexfmt.ADLER_MODULUS < dexfmt.ADLER_WRONG_MODULUS)


class TestDexHeader(unittest.TestCase):
    def test_parse_valid_header(self):
        data = make_dex()
        h = dexfmt.parse_header(data)
        self.assertEqual(h.magic, b"dex\n035\x00")
        self.assertEqual(h.version, 35)
        self.assertEqual(h.file_size, len(data))
        self.assertEqual(h.header_size, 112)
        self.assertEqual(h.endian_tag, dexfmt.ENDIAN_CONSTANT)

    def test_wrong_magic_raises(self):
        bad = bytearray(make_dex())
        bad[0:4] = b"zip\n"
        with self.assertRaises(dexfmt.DexFormatError):
            dexfmt.parse_header(bytes(bad))

    def test_too_short_raises(self):
        with self.assertRaises(dexfmt.DexFormatError):
            dexfmt.parse_header(b"dex\n035\x00" + b"\x00" * 10)


class TestDexVerification(unittest.TestCase):
    def test_valid_dex_passes_both_checks(self):
        dex = dexfmt.analyze(make_dex(), "ok.dex")
        self.assertTrue(dex.checksum_ok, "合法 DEX 的校验和应通过")
        self.assertTrue(dex.signature_ok, "合法 DEX 的签名应通过")
        self.assertTrue(dex.is_valid)
        self.assertEqual(dex.structural_errors, [])

    def test_tampered_payload_fails_checksum(self):
        """改动载荷但不重算校验和 —— 正是 ART 会拒绝加载的情形。"""
        data = bytearray(make_dex(b"\x00" * 256))   # 载荷要够长才能改内部字节
        data[150] ^= 0xFF
        dex = dexfmt.analyze(bytes(data), "tampered.dex")
        self.assertFalse(dex.checksum_ok, "被篡改的 DEX 校验和应失败")
        self.assertFalse(dex.is_valid)

    def test_tampered_header_signature_fails(self):
        data = bytearray(make_dex())
        data[33] ^= 0x01          # 破坏头部的 signature 字段本身
        dex = dexfmt.analyze(bytes(data), "badsig.dex")
        self.assertFalse(dex.signature_ok)
        self.assertFalse(dex.is_valid)

    def test_wrong_header_size_is_reported(self):
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 36, 0x60)   # header_size 应为 0x70
        struct.pack_into("<I", data, 8, zlib.adler32(bytes(data)[12:]) & 0xFFFFFFFF)
        dex = dexfmt.analyze(bytes(data), "badhdr.dex")
        self.assertTrue(any("header_size" in e for e in dex.structural_errors))

    def test_file_size_mismatch_is_reported(self):
        data = bytearray(make_dex())
        struct.pack_into("<I", data, 32, 999999)
        struct.pack_into("<I", data, 8, zlib.adler32(bytes(data)[12:]) & 0xFFFFFFFF)
        dex = dexfmt.analyze(bytes(data), "badsize.dex")
        self.assertTrue(any("file_size" in e for e in dex.structural_errors))

    def test_no_verify_skips_computation(self):
        dex = dexfmt.analyze(make_dex(), "skip.dex", verify=False)
        self.assertIsNone(dex.checksum_ok)
        self.assertIsNone(dex.signature_ok)
        self.assertIsNone(dex.checksum_computed)


class TestExplainChecksum(unittest.TestCase):
    def test_reports_correct_modulus_match(self):
        data = make_dex()
        stored = struct.unpack_from("<I", data, 8)[0]
        info = dexfmt.explain_checksum(data, stored)
        self.assertTrue(info["correct_matches_stored"])
        self.assertFalse(info["wrong_mod65536_matches_stored"])
        self.assertEqual(info["covered_bytes"], len(data) - 12)

    def test_detects_dex_written_with_wrong_modulus(self):
        """
        模拟「写入方用错模数」的包：把 65536 模数下的值写进头部。
        诊断函数应当精确指出这一点——这正是 ART 报错信息做不到的。
        """
        data = bytearray(make_dex())
        wrong = dexfmt.adler32_mod(bytes(data)[12:], dexfmt.ADLER_WRONG_MODULUS)
        struct.pack_into("<I", data, 8, wrong)

        dex = dexfmt.analyze(bytes(data), "wrongmod.dex")
        self.assertFalse(dex.checksum_ok, "错误模数写出的包必须判定为校验失败")

        info = dexfmt.explain_checksum(bytes(data), wrong)
        self.assertTrue(info["wrong_mod65536_matches_stored"],
                        "诊断应识别出「记录值恰好等于 65536 模数下的结果」")
        self.assertFalse(info["correct_matches_stored"])


class TestMapParsing(unittest.TestCase):
    def test_parse_map_reads_items(self):
        # 手工拼一个 map_list：2 个条目。map_off=0 在 DEX 里表示「无映射表」，
        # 所以这里必须放在一个非 0 偏移上（前面垫 8 字节）。
        map_bytes = b"\x00" * 8 + struct.pack("<I", 2)
        map_bytes += struct.pack("<HHII", 0x0000, 0, 1, 0)            # header_item
        map_bytes += struct.pack("<HHII", 0x2001, 0, 38238, 1526308)  # code_item
        items = dexfmt.parse_map(map_bytes, 8)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].type_name, "header_item")
        self.assertEqual(items[1].type_name, "code_item")
        self.assertEqual(items[1].offset, 1526308)
        self.assertEqual(items[1].size, 38238)

    def test_parse_map_with_bad_offset_returns_empty(self):
        self.assertEqual(dexfmt.parse_map(b"\x00" * 8, 99999), [])

    def test_parse_map_offset_zero_means_no_map(self):
        """map_off==0 是「无映射表」的合法表示，不应被当成错误。"""
        self.assertEqual(dexfmt.parse_map(struct.pack("<I", 2) + b"\x00" * 24, 0), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
