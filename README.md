# apk-analyzer

A dependency-free Android APK / DEX structure analyzer.

Parses the ZIP container, DEX headers, and APK signature layout **from the raw
byte format spec** — no `zipfile`, no `androguard`, no `apkutils`. Standard
library only.

The point is not to wrap existing libraries. The point is that when a repackaged
APK refuses to start, the answer lives in bytes that libraries hide from you:
the DEX `checksum` field, the `extra` length of a local file header, the order of
central-directory entries. This tool shows those bytes and verifies them.

---

## Why it exists

Repackaging an APK and having it crash on launch with
`ClassNotFoundException: MyApp` is a bad place to be. The runtime message points
at a missing class. The actual cause is usually that ART refused to load the
entire `classes2.dex` because its integrity fields did not match.

Two fields decide that:

| Field | Offset | Algorithm | Covers |
|---|---|---|---|
| `signature` | 32 | SHA-1 | `data[32:]` |
| `checksum` | 12 | Adler-32, **modulus 65521** | `data[12:]` |

The modulus is the trap. `65521` is the largest prime below 2¹⁶ — it is part of
the Adler-32 definition, but it is easy to reach for `65536` instead (the natural
modulus for a 16-bit accumulator). Both values look plausible; only one is
correct. When they disagree, the checksum silently fails and the whole DEX is
rejected.

`--explain-checksum` computes both and tells you which one your file was written
with.

---

## Features

- **Hand-written ZIP reader** — EOCD scan, central directory, local header
  resolution, ZIP64 detection, per-entry CRC-32 verification.
- **DEX header analysis** — all 20 header fields, section counts, `map_list`
  enumeration, and verification of both `checksum` and `signature`.
- **Checksum forensics** — `--explain-checksum` reports the spec-correct value,
  the wrong-modulus value, and which one matches what is stored.
- **APK signature layout** — v1 (`META-INF/*.SF|RSA|DSA|EC`) detection and the
  v2/v3 APK Signing Block (`APK Sig Block 42`) located by its position relative
  to the central directory.
- **Archive diffing** — `--compare` proves whether a repack was *minimal*:
  how many entries stayed byte-identical, which changed, and why.
- **Zero dependencies** — pure standard library, Python 3.9+.
- **Machine-readable** — `--json` for CI pipelines; non-zero exit on integrity
  failure, so it can gate a build.

---

## Install

Nothing to install:

```bash
git clone <this-repo>
cd apk-analyzer
python analyze.py app.apk
```

Optional (as a module):

```bash
python -m apk_analyzer.cli app.apk
```

---

## Usage

```bash
python analyze.py app.apk
python analyze.py app.apk --explain-checksum
python analyze.py app.apk --list 40
python analyze.py app.apk --json
python analyze.py original.apk --compare repacked.apk --deep
python analyze.py app.apk --ascii          # console without UTF-8 support
```

### Integrity report

```
APK         : base-patched.apk
大小        : 17.38 MB  (18219122 字节)
归档条目    : 2495
APK 签名块  : 未检出 v2/v3 签名块
v1 签名文件 : 2 个签名文件, 含 MANIFEST.MF
              META-INF/CERT.SF
              META-INF/CERT.RSA

DEX 文件（3 个）

  ✓ classes2.dex   7.33 MB   DEX 035
      checksum     : 记录 0x6d9a7177  实算 0x6d9a7177   [PASS]
      signature    : 6e9282070b80dd177a41db74…   [PASS]
      code_item    : 偏移 4227416, 共 36172 项
```

### Checksum forensics

```
校验和诊断（DEX 规范：Adler-32 范围 data[12:]，模数 65521）

  classes2.dex
      头部记录值        : 0x6d9a7177
      规范值(模 65521)  : 0x6d9a7177   匹配
      错误值(模 65536)  : 0x3f1c8a02   不匹配
```

### Minimal-repack verification

```
双包差异比对（验证「最小改动重打包」）

  A(基准) : base.apk            2495 个条目
  B(对照) : base-patched.apk    2495 个条目

  字节级一致 : 2491
  内容有变化 : 2
  仅 B 有    : 2
  仅 A 有    : 2

  ── 内容发生变化的条目 ──
    ⚠ classes2.dex
        CRC 0x9c60bbf9→0xfee33ccd; 压缩后 2744782→2955762
    ⚠ META-INF/MANIFEST.MF
        CRC 0x6773afde→0x712ba539; 原始 278080→277981

  结论: ✓ 2491/2495 个条目字节级未变（99.84%）
        改动高度集中，符合「最小改动重打包」预期
```

Note the changed `classes2.dex` above: its **uncompressed** size is unchanged
while its compressed size grew. That is exactly the signature of a size-neutral
bytecode edit — which is what a correct minimal repack should look like.

---

## How the verification is trusted

A hand-written parser is only worth as much as its correctness evidence, so:

- `tests/test_zipfmt.py` cross-checks every parsed field — names, CRC, both size
  fields, compression method — against the standard library's `zipfile`, and
  re-extracts each entry through the *self-computed* `data_offset` to confirm the
  bytes match the original input. If the offset arithmetic were off by one byte,
  those tests go red.
- `tests/test_dexfmt.py` verifies the pure-Python `adler32_mod()` against
  `zlib.adler32` across random and edge-case inputs, then asserts that modulus
  65521 and 65536 genuinely diverge, then drives DEX verification in both
  directions with synthetic headers.
- `tests/test_compare.py` covers identical / modified / added / removed entries
  and checks that a whole-archive rewrite is *not* reported as minimal.

```bash
python -m unittest discover -s tests -t .
# Ran 37 tests ... OK
```

---

## Design notes

**Why not use `zipfile`?** Because it reports the answer, not the evidence. It
will not tell you an entry's `extra` field length, whether the data-descriptor
flag is set, or in what order entries appear in the central directory — and those
three are precisely what "minimal change repackaging" depends on.

**Why is `adler32_mod()` not loop-modulo?** Taking the modulus inside the loop
costs a `%` per byte. Since `a` stays congruent to its exact value and `b` is a
sum of such values, deferring modulo to the end is mathematically identical.
Python integers do not overflow, so this is safe and measurably faster on
multi-megabyte DEX files. The equivalence is asserted against `zlib` in tests.

**What is deliberately *not* implemented:** DEX string/type/class index
resolution, bytecode disassembly, resource decoding, and AndroidManifest binary
XML parsing. Those are large subsystems; this tool is about container- and
integrity-level facts.

---

## Limitations

- Little-endian DEX only (`endian_tag` reverse-endian files are detected and
  reported, but not parsed).
- v1 signing is detected structurally; certificate chains inside the PKCS#7 blob
  are not decoded.
- v2/v3 signature block is located and measured, but its id-value pairs are not
  verified cryptographically. For authoritative signing verification use
  `apksigner verify`.
- Only `stored` and `deflate` entry compression is supported.

This tool reports structure and integrity. It does **not** modify archives, and
it contains no patching or bypass capability.

---

## License

MIT
