"""
apk-analyzer — Android APK / DEX 结构分析器。

零第三方依赖：ZIP 归档、DEX 头部、AndroidManifest 二进制 XML
全部按格式规范手写解析，不借助 zipfile / androguard / apkutils。
"""

from . import dexfmt, zipfmt

__all__ = ["dexfmt", "zipfmt", "__version__"]
__version__ = "0.1.0"
