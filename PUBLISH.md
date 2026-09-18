# 把 apk-analyzer 发布到 GitHub

## 为什么要做这件事

你的简历和作品站上都写了这个工具是「**开源**」。但**没有一个可点击的链接，面试官就无法验证**——
"开源"就成了一句无法兑现的话。这比不写更糟。

而且 GitHub 本身就是一个**独立于简历的评价资产**：面试官看到你有真实提交记录、
有 README、有测试，比看简历上一行字可信得多。

**发布后你要把仓库地址回填到两个地方**（两处都留了 `USERNAME` 占位符）：

| 位置 | 文件 |
|---|---|
| 作品站 | `personal-site/index.html`、`personal-site/en/index.html` |
| 包元数据 | `apk-analyzer/pyproject.toml` |

> `deploy/build.py` 会检查作品站里是否还有 `USERNAME` 占位符，
> **不填完不会让你打包**——防止你带着死链接上线。

---

## 方案 A：网页上传（不需要装任何东西，5 分钟）

适合第一次发布。

### 1. 建仓库

1. 打开 https://github.com/new
2. **Repository name** 填 `apk-analyzer`
3. **Description** 填：
   `Dependency-free Android APK / DEX structure analyzer — hand-written ZIP, DEX and APK signature parsing`
4. 选 **Public**（要公开，否则面试官看不到）
5. **不要**勾 "Add a README file"（我们已经有 README 了，勾了会冲突）
6. 点 **Create repository**

### 2. 上传文件

在新仓库页面点 **uploading an existing file**，然后把下面这些**拖进去**：

```
apk-analyzer/
├── analyze.py
├── LICENSE
├── README.md
├── README.zh-CN.md
├── pyproject.toml
├── .gitignore
├── apk_analyzer/
│   ├── __init__.py
│   ├── cli.py
│   ├── compare.py
│   ├── dexfmt.py
│   └── zipfmt.py
└── tests/
    ├── __init__.py
    ├── test_compare.py
    ├── test_dexfmt.py
    └── test_zipfmt.py
```

⚠️ **不要把 `__pycache__/` 拖进去**（那是 Python 编译缓存，已有 `.gitignore` 忽略它）。

> GitHub 网页上传**支持拖文件夹**，但有时会漏掉隐藏文件（`.gitignore` 以点开头）。
> 上传完检查一下 `.gitignore` 在不在；不在就单独再传一次。

### 3. 提交

Commit message 填：

```
Initial release: dependency-free APK/DEX structure analyzer

- Hand-written ZIP central-directory parser (no zipfile)
- DEX header parsing + Adler-32 (mod 65521) / SHA-1 verification
- APK v1 signature files and v2/v3 Signing Block detection
- Archive diff mode proving minimal-change repackaging
- 37 unit tests, ZIP parser cross-validated against stdlib zipfile
```

点 **Commit changes**。

### 4. 回填链接

你的仓库地址形如 `https://github.com/你的用户名/apk-analyzer`。
把它填进上面表格里的两个位置（把 `USERNAME` 替换掉）。

---

## 方案 B：命令行（推荐，迟早要会）

`git` 是版本控制工具，**几乎所有技术岗位都要求会用**。既然要投技术岗，装它值得。

### 1. 装 git

```powershell
# 方式一：Windows 包管理器
winget install --id Git.Git -e

# 方式二：官网下载 https://git-scm.com/download/win
```

装完**重开一个终端**，验证：

```powershell
git --version
```

### 2. 一次性配置（只需做一次）

```powershell
git config --global user.name "Geng Shijia"
git config --global user.email "3046465294@qq.com"
git config --global init.defaultBranch main
```

> 建议把邮箱换成你在 GitHub 上用的邮箱，这样提交记录才会关联到你的账号。

### 3. 初始化并提交

```powershell
cd "D:\DSH Desk\dsh\apk-analyzer"

git init
git add .
git status          # ← 先看一眼，确认 __pycache__ 没有被加进去
git commit -m "Initial release: dependency-free APK/DEX structure analyzer"
```

### 4. 推到 GitHub

先在 https://github.com/new 建一个**空的** `apk-analyzer` 仓库（同方案 A 第 1 步），然后：

```powershell
git remote add origin https://github.com/你的用户名/apk-analyzer.git
git branch -M main
git push -u origin main
```

首次推送会弹出浏览器让你登录 GitHub 授权，点同意即可。

---

## 发布之后（这些才是真正加分的部分）

### 1. 确认 README 在页面上显示正常

README 是别人打开仓库**第一眼看到的东西**。检查：
- 代码块有没有正常高亮
- 表格有没有正常渲染
- 中文的 `README.zh-CN.md` 能不能点开

### 2. 给仓库加上 Topics（标签）

仓库页面右上角 ⚙️ → Topics，填：

```
android  apk  dex  zip  adler32  reverse-engineering  forensics
qa  testing  python  no-dependencies  file-format
```

这些标签能让别人搜到你，也是"你懂这个领域"的信号。

### 3. 打一个 Release

仓库页面右侧 **Releases** → **Create a new release**：

- Tag: `v0.1.0`
- Title: `v0.1.0 — first public release`
- 说明里直接复制 README 的 Features 段落

**有 Release 的仓库看起来更正式**，面试官会认为你真的在维护它。

### 4. 持续提交，别只提交一次

**只有一个 "Initial commit" 的仓库，说服力有限。** 发布之后继续改：

- 加一个 `--manifest` 参数输出权限清单
- 加 AndroidManifest 二进制 XML 解析
- 修一个小 bug 并发一个 issue + PR（自己发自己合也算数）

**每次提交都是一条时间记录**，它比简历上任何形容词都有说服力。

---

## ⚠️ 发布前检查（重要）

| ☐ | 检查项 | 为什么 |
|---|---|---|
| ☐ | 仓库里**没有任何真实 APK 文件** | `.gitignore` 已排除 `*.apk`；**别人 App 的安装包不能上传** |
| ☐ | 代码里**没有真实 App 的包名** | 你当初处理的那个应用包名不能出现在公开仓库里 |
| ☐ | README 里**没有提到**"破解""去除功能""绕过验证" | 本工具是**只读分析**工具，定位就停留在结构分析与完整性验证 |
| ☐ | 没有提交任何密钥、证书、个人隐私文件 | 公开仓库 = 所有人可见，删掉也留在历史里 |
| ☐ | `git status` 里没有 `__pycache__` | 缓存文件不该进版本库 |

> 这几条和求职作战包里「防骗清单第六组」是同一套红线：**技术能力全部展示，
> 但把目标应用的身份和"改动目的"从公开材料里拿掉。**

---

## 如果你现在不想发 GitHub

还有一条替代路线：**把源码放在你自己的服务器上对外下载**。

但你已经有服务器了，而 GitHub 的价值不只是托管——它还有
**提交历史、issue、star、别人能看到的公开记录**。对找工作来说，
GitHub 明显更划算。建议还是发。
