#!/usr/bin/env python3
"""apk-analyzer 便捷入口（无需安装，直接运行）。

    python analyze.py app.apk
    python analyze.py app.apk --json
    python analyze.py app.apk --explain-checksum
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from apk_analyzer.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
