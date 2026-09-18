# apk-analyzer

零第三方依赖的 Android APK / DEX 结构分析器。

ZIP 容器、DEX 头部、APK 签名布局全部**按格式规范手写解析**——不使用
`zipfile`、`androguard`、`apkutils`，只用 Python 标准库。

目的不是包一层现成库。而是因为：当一个重打包后的 APK 启动失败时，
答案就藏在那些被库藏起来的字节里——DEX 的 `checksum` 字段、本地文件头的
`extra` 长度、中央目录的条目顺序。本工具就是把这些字节摆出来并验证它们。

---

## 它解决什么问题

改完 APK 重打包，一启动就崩，报 `ClassNotFoundException: MyApp`。
这个报错指向"找不到类"，但真正的原因通常是：**ART 拒绝了整个 `classes2.dex`**，
因为它头部的完整性字段对不上。ART 不会告诉你这一点。

决定成败的是两个字段：

| 字段 | 偏移 | 算法 | 覆盖范围 |
|---|---|---|---|
| `signature` | 32 | SHA-1 | `data[32:]` |
| `checksum` | 12 | Adler-32，**模数 65521** | `data[12:]` |

**模数就是那个坑。** `65521` 是小于 2¹⁶ 的最大质数，它是 Adler-32 定义的一部分；
但实现时非常容易顺手写成 `65536`（16 位累加器最自然的模数）。
两个值看起来都很合理，但只有一个是对的——写错了校验和就静默失败，
整个 dex 被拒绝加载，而报错信息完全指不到这里。

`--explain-checksum` 会把两个值都算出来，告诉你文件是用哪个写的。

---

## 功能

- **手写 ZIP 解析**：EOCD 回扫、中央目录、本地文件头偏移推导、ZIP64 探测、
  逐条目 CRC-32 校验。
- **DEX 头部分析**：全部 20 个头字段、各段条目数、`map_list` 枚举，
  以及 `checksum` 与 `signature` 的双向验证。
- **校验和取证**：`--explain-checksum` 同时给出规范值、错误模数值、
  以及哪一个与文件里记录的值相符。
- **签名布局**：v1（`META-INF/*.SF|RSA|DSA|EC`）检出 +
  v2/v3 APK Signing Block（`APK Sig Block 42`）按其在中央目录前的位置定位。
- **双包差异比对**：`--compare` 证明一次重打包是否**最小改动**——
  多少条字节级未变、哪些变了、为什么变。
- **零依赖**：纯标准库，Python 3.9+。
- **可机读**：`--json` 供 CI 使用；完整性失败时返回非 0 退出码，可直接卡门。

---

## 用法

无需安装：

```bash
git clone <this-repo>
cd apk-analyzer
python analyze.py app.apk
```

```bash
python analyze.py app.apk                        # 概览 + 完整性验证
python analyze.py app.apk --explain-checksum     # 校验和深度诊断
python analyze.py app.apk --list 40              # 列出前 40 个归档条目
python analyze.py app.apk --json                 # JSON 输出
python analyze.py a.apk --compare b.apk --deep   # 双包比对（深度模式）
python analyze.py app.apk --ascii                # 控制台不支持 UTF-8 时使用
```

### 典型输出：完整性验证

```
DEX 文件（3 个）

  ✓ classes2.dex   7.33 MB   DEX 035
      checksum     : 记录 0x6d9a7177  实算 0x6d9a7177   [PASS]
      signature    : 6e9282070b80dd177a41db74…   [PASS]
      code_item    : 偏移 4227416, 共 36172 项
```

### 典型输出：校验和诊断

```
校验和诊断（DEX 规范：Adler-32 范围 data[12:]，模数 65521）

  classes2.dex
      头部记录值        : 0x6d9a7177
      规范值(模 65521)  : 0x6d9a7177   匹配
      错误值(模 65536)  : 0x3f1c8a02   不匹配
```

### 典型输出：验证「最小改动重打包」

```
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
```

注意上面 `classes2.dex`：**原始大小没变、压缩后大小变大**。
这正是「同尺寸字节码修改」的特征——一次正确的重打包就应该是这个样子。

---

## 验证方式（凭什么相信它是对的）

手写解析器的价值，取决于它的正确性证据。所以：

- `tests/test_zipfmt.py` 把解析出的每个字段——条目名、CRC、两个长度字段、
  压缩方法——与标准库 `zipfile` **逐项交叉验证**；并且用**自己算出的
  `data_offset`** 去原始字节里取数据解压，确认结果与输入逐字节相同。
  偏移算错一个字节，这些测试立刻变红。
- `tests/test_dexfmt.py` 用随机与边界数据把纯 Python 的 `adler32_mod()`
  与 `zlib.adler32` 逐值比对，再断言模数 65521 与 65536 **确实产生不同结果**，
  最后用合成头部正反两个方向驱动 DEX 验证逻辑。
- `tests/test_compare.py` 覆盖一致 / 修改 / 新增 / 删除四条路径，
  并断言「整包重写」不会被误判为最小改动。

```bash
python -m unittest discover -s tests -t .
# Ran 37 tests ... OK
```

---

## 设计说明

**为什么不用 `zipfile`？** 因为它只给结果，不给证据。它不会告诉你某个条目的
`extra` 字段有多长、数据描述符标志有没有置位、条目在中央目录里是什么顺序——
而这三样恰恰是「最小改动重打包」的成败关键。

**`adler32_mod()` 为什么不逐字节取模？** 循环里取模要付每字节一次 `%` 的代价。
由于 `a` 始终与其精确值同余、`b` 又是这些值的和，把取模推迟到最后在数学上完全等价。
Python 整数不会溢出，所以这对几 MB 的 DEX 是安全且显著更快的。该等价性由测试对 `zlib` 断言。

**刻意没做的部分**：DEX 字符串/类型/类索引解析、字节码反汇编、资源解码、
AndroidManifest 二进制 XML 解析。这些是庞大的子系统；本工具聚焦于
容器层与完整性层的事实。

---

## 已知限制

- 仅支持小端 DEX（反向端序文件会被检出并报告，但不解析）。
- v1 签名只做结构性检出，不解码 PKCS#7 里的证书链。
- v2/v3 签名块只做定位与尺寸测量，不做密码学验证；
  权威验签请用 `apksigner verify`。
- 仅支持 `stored` 与 `deflate` 两种条目压缩方式。

本工具只报告结构与完整性。它**不修改**归档，也不包含任何打补丁或绕过能力。

---

## 许可

MIT
