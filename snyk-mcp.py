# mcp_scan_utf8.py
import os
import sys
import json
import time
import subprocess
import threading
import queue
import re
from pathlib import Path
from shutil import which

SEVERITY = os.getenv("SNYK_SEVERITY", "low")
PY_CMD   = os.getenv("SNYK_PYTHON_CMD")  # e.g., python or python3

# Regex to detect hard errors in stderr (case-insensitive)
HARD_ERR_RE = re.compile(r'(^|\s)(ERR|ERROR|FATAL)(\s|:)', re.IGNORECASE)

def resolve_snyk_path():
    """Return absolute path to snyk CLI by searching PATH. Raise if not found."""
    p = which("snyk")
    if not p:
        p = which("snyk.cmd") or which("snyk.exe")
    if not p:
        raise RuntimeError("Snyk CLI not found in PATH. Install Snyk or fix PATH.")
    return p

def start_mcp():
    """Start Snyk MCP with --disable-trust. UTF-8 streams. Exit only on hard stderr errors."""
    snyk_path = resolve_snyk_path()
    win = os.name == "nt"
    env = os.environ.copy()
    env["SNYK_DISABLE_EMOJIS"] = env.get("SNYK_DISABLE_EMOJIS", "true")
    env["PYTHONUTF8"] = "1"

    use_shell = win and snyk_path.lower().endswith((".cmd", ".bat"))
    if use_shell:
        cmd = f"\"{snyk_path}\" mcp -t stdio --experimental --disable-trust"
        p = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1, env=env
        )
    else:
        cmd = [snyk_path, "mcp", "-t", "stdio", "--experimental", "--disable-trust"]
        p = subprocess.Popen(
            cmd, shell=False,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1, env=env
        )

    out_q = queue.Queue()

    def read_stdout():
        for line in p.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                out_q.put(obj)
            except json.JSONDecodeError:
                print("[RAW]", line)

    def read_stderr():
        # Print all stderr lines; exit only on "hard" errors
        for line in p.stderr:
            msg = line.rstrip()
            if not msg:
                continue
            print("[STDERR]", msg)
            if HARD_ERR_RE.search(msg) or "exit status" in msg.lower():
                try:
                    p.terminate()
                except Exception:
                    pass
                os._exit(1)

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()

    req_id = 1
    def call(method, params=None, timeout=180):
        nonlocal req_id
        request = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            request["params"] = params
        if p.stdin.closed:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -1, "message": "stdin closed"}}
        p.stdin.write(json.dumps(request) + "\n")
        p.stdin.flush()
        current_id = req_id
        req_id += 1

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                obj = out_q.get(timeout=0.25)
                if isinstance(obj, dict) and obj.get("id") == current_id:
                    return obj
            except queue.Empty:
                pass
        return {"jsonrpc": "2.0", "id": current_id, "error": {"code": -1, "message": "timeout"}}

    return p, call

def pretty(title, obj):
    print(f"\n=== {title} ===")
    try:
        print(json.dumps(obj, indent=2, ensure_ascii=False))
    except Exception:
        print(obj)

def collect_findings(obj):
    findings = []
    def walk(o):
        if isinstance(o, list):
            for v in o:
                walk(v)
        elif isinstance(o, dict):
            severity = (o.get("severity") or o.get("severity_level") or "").lower()
            title = o.get("title") or o.get("message") or o.get("id") or o.get("ruleId")
            pkg = o.get("packageName") or o.get("package") or o.get("dep")
            location = o.get("file") or o.get("path") or o.get("location") or o.get("filename")
            if severity and (title or pkg or location):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "package": pkg,
                    "location": location
                })
            for v in o.values():
                walk(v)
    walk(obj or {})
    return findings

def count_by_severity(findings):
    levels = ["critical", "high", "medium", "low", "unknown"]
    counter = {k: 0 for k in levels}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev not in counter:
            sev = "unknown"
        counter[sev] += 1
    return counter

def sca_failed_like(result_obj) -> bool:
    if not result_obj:
        return True
    if result_obj.get("error"):
        return True
    res = result_obj.get("result") or {}
    body = ""
    for c in res.get("content", []):
        if isinstance(c, dict) and c.get("type") == "text":
            body += c.get("text", "")
    body_lower = body.lower()
    if "failed to get dependencies" in body_lower:
        return True
    if "snyk-cli-0000" in body_lower:
        return True
    if not res and not body:
        return True
    return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python mcp_scan_utf8.py <target_path>")
        sys.exit(2)

    target = Path(sys.argv[1]).resolve()
    if not target.exists():
        print(f"Target does not exist: {target}")
        sys.exit(2)

    if (target / "pom.xml").exists():
        print("[NOTE] pom.xml detected; Maven may be required for SCA to resolve dependencies.")

    print("[+] Launching Snyk MCP (stdio, --disable-trust)")
    p, call = start_mcp()

    tools = call("tools/list", {}, timeout=15)
    pretty("tools/list", tools)

    # --- SCA ---
    sca_args = {"path": str(target), "severity_threshold": SEVERITY}
    if PY_CMD:
        sca_args["command"] = PY_CMD  # only for Python projects
    sca = call("tools/call", {"name": "snyk_sca_scan", "arguments": sca_args}, timeout=600)
    pretty("SCA raw response", sca)
    if sca and sca.get("error"):
        print("\n[SCA error message]", sca["error"].get("message"))

    # --- CODE (always run) ---
    if sca_failed_like(sca):
        print("[INFO] SCA failed or produced no usable result. Running Code scan only.")
    code = call("tools/call", {
        "name": "snyk_code_scan",
        "arguments": {"path": str(target), "severity_threshold": SEVERITY}
    }, timeout=900)
    pretty("CODE raw response", code)
    if code and code.get("error"):
        print("\n[CODE error message]", code["error"].get("message"))

    # --- Summary ---
    sca_findings  = collect_findings(sca if not sca_failed_like(sca) else {})
    code_findings = collect_findings(code)
    print("\n== Summary ==")
    print("[SCA ]", count_by_severity(sca_findings))
    print("[CODE]", count_by_severity(code_findings))

    try:
        p.terminate()
    except Exception:
        pass

if __name__ == "__main__":
    main()
