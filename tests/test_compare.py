"""
compare 自测：验证「最小改动重打包」判定逻辑。

判定基于 ZIP 条目记录的 (压缩方法, CRC-32, 压缩后大小, 原始大小)。
这里用合成归档覆盖一致 / 修改 / 新增 / 删除四条路径。
"""

import io
import unittest
import zipfile

from apk_analyzer import compare


def build_zip(payloads: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in payloads.items():
            zf.writestr(name, data)
    return buf.getvalue()


def write_tmp(tmpdir, name, blob):
    import os

    path = os.path.join(tmpdir, name)
    with open(path, "wb") as fh:
        fh.write(blob)
    return path


class TestCompare(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.mkdtemp(prefix="apk-analyzer-test-")
        self.base = {
            "classes.dex": b"AAA" * 500,
            "classes2.dex": b"BBB" * 500,
            "res/values/strings.xml": b"<resources/>" * 20,
            "assets/blob.bin": b"\x00\x01\x02\x03" * 300,
            "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
        }

    def _pair(self, modified: dict[str, bytes]):
        a = write_tmp(self.tmp, "a.apk", build_zip(self.base))
        b = write_tmp(self.tmp, "b.apk", build_zip(modified))
        return a, b

    def test_identical_archives(self):
        a, b = self._pair(dict(self.base))
        result = compare.compare(a, b)
        self.assertEqual(len(result.changed), 0)
        self.assertEqual(len(result.added), 0)
        self.assertEqual(len(result.removed), 0)
        self.assertEqual(len(result.identical), len(self.base))
        self.assertTrue(result.minimal)

    def test_single_entry_changed_is_minimal(self):
        mod = dict(self.base)
        mod["classes2.dex"] = b"CCC" * 500          # 只改一个条目
        a, b = self._pair(mod)
        result = compare.compare(a, b)

        self.assertEqual([d.name for d in result.changed], ["classes2.dex"])
        self.assertEqual(len(result.identical), len(self.base) - 1)
        self.assertTrue(result.minimal, "只改一个条目应判定为最小改动")
        self.assertIn("CRC", result.changed[0].detail)

    def test_extra_entry_detected(self):
        mod = dict(self.base)
        mod["META-INF/CERT.RSA"] = b"fake signature"
        a, b = self._pair(mod)
        result = compare.compare(a, b)
        self.assertEqual([d.name for d in result.added], ["META-INF/CERT.RSA"])

    def test_missing_entry_detected(self):
        mod = dict(self.base)
        del mod["assets/blob.bin"]
        a, b = self._pair(mod)
        result = compare.compare(a, b)
        self.assertEqual([d.name for d in result.removed], ["assets/blob.bin"])

    def test_massive_change_is_not_minimal(self):
        """所有条目都变了 —— 典型「整包重压缩」，必须判为非最小改动。"""
        mod = {name: data + b"!" for name, data in self.base.items()}
        a, b = self._pair(mod)
        result = compare.compare(a, b)
        self.assertEqual(len(result.changed), len(self.base))
        self.assertFalse(result.minimal, "全量变化不应被判为最小改动")

    def test_deep_mode_sets_hashes(self):
        mod = dict(self.base)
        mod["classes.dex"] = b"ZZZ" * 500
        a, b = self._pair(mod)
        result = compare.compare(a, b, deep=True)
        changed = result.changed[0]
        self.assertTrue(changed.sha_a and changed.sha_b)
        self.assertNotEqual(changed.sha_a, changed.sha_b)

    def test_deep_mode_identical_hashes_match(self):
        a, b = self._pair(dict(self.base))
        result = compare.compare(a, b, deep=True)
        for d in result.identical:
            self.assertEqual(d.sha_a, d.sha_b, f"{d.name} 深度比对应完全一致")


if __name__ == "__main__":
    unittest.main(verbosity=2)
