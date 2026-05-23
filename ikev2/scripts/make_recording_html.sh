#!/usr/bin/env bash
# Build browsable HTML from demo_recording.log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$ROOT/docs/output/demo_recording.log"
OUT="$ROOT/docs/output/demo_recording.html"

if [ ! -f "$LOG" ]; then
    echo "Run ./scripts/record_demo.sh first" >&2
    exit 1
fi

python3 <<PY
import html
from pathlib import Path
log = Path("$LOG").read_text()
body = html.escape(log)
html_out = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IKEv2 LB Demo Recording</title>
<style>
body {{ font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 1em; }}
pre {{ white-space: pre-wrap; line-height: 1.4; }}
h1 {{ color: #4fc3f7; font-family: sans-serif; }}
</style></head><body>
<h1>IKEv2 Load Balancer — Session Recording</h1>
<pre>{body}</pre>
</body></html>"""
Path("$OUT").write_text(html_out)
print("Wrote", "$OUT")
PY
