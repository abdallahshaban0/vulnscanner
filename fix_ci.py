"""
Run this script from inside your vulnscanner-final folder to fix the CI errors.
Usage: python fix_ci.py
"""
import os

fixes = {
    os.path.join("modules", "dns_recon.py"): [
        ("import socket\nimport concurrent.futures\nfrom typing import Dict, List, Optional",
         "import socket\nimport concurrent.futures\nfrom typing import Dict, List"),
        ("import requests\n", ""),
    ],
    os.path.join("modules", "http_scanner.py"): [
        ("from typing import Dict, List, Optional",
         "from typing import Dict, List"),
        ("from urllib.parse import urlparse, urljoin",
         "from urllib.parse import urlparse"),
    ],
    os.path.join("modules", "port_scanner.py"): [
        ("import socket\nimport concurrent.futures\nimport time\n",
         "import socket\nimport concurrent.futures\n"),
    ],
    os.path.join("modules", "report_generator.py"): [
        ("import json\nimport os\nfrom datetime import datetime",
         "import json\nfrom datetime import datetime"),
    ],
}

for filepath, replacements in fixes.items():
    if not os.path.exists(filepath):
        print(f"SKIP (not found): {filepath}")
        continue
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    original = content
    for old, new in replacements:
        content = content.replace(old, new)
    if content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"FIXED: {filepath}")
    else:
        print(f"ALREADY OK: {filepath}")

print("\nDone! Now run:")
print("  git add .")
print('  git commit -m "Fix: remove unused imports"')
print("  git push")
