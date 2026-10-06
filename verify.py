"""One-shot verification for the X12 envelope audit service.

Runs, in order:
  1. an API readiness wait (the container health gate),
  2. the code test suite (pytest),
  3. an application build check (byte-compile + ASGI import + routes),
  4. HTTP smoke tests with valid and corrupted envelopes.

Exits 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
HEALTH_WAIT_SECONDS = int(os.environ.get("VERIFY_HEALTH_WAIT", "60"))
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024


# ------------------------------------------------------------ message builder


def isa_segment(control: str = "000000001") -> str:
    fields = [
        "ISA",
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        "SENDER".ljust(15),
        "ZZ",
        "RECEIVER".ljust(15),
        "260101",
        "1200",
        "U",
        "00401",
        control.ljust(9),
        "0",
        "T",
        ">",
    ]
    segment = "*".join(fields) + "~"
    assert len(segment) == 106
    return segment


def build_message(isa_control: str = "000000001", groups=None) -> bytes:
    if groups is None:
        groups = [
            [("0001", ["BIG*20260101*PO0001"]), ("0002", ["BIG*20260101*PO0002", "REF*ZZ"])],
            [("0003", ["BIG*20260101*PO0003"])],
        ]
    parts = [isa_segment(isa_control)]
    for index, txns in enumerate(groups, start=1):
        gs_control = str(index)
        parts.append(f"GS*PO*SENDER*RECEIVER*20260101*1200*{gs_control}*X*004010~")
        for st_control, data in txns:
            lines = [f"ST*850*{st_control}", *data]
            lines.append(f"SE*{len(lines) + 1}*{st_control}")
            parts.append("".join(line + "~" for line in lines))
        parts.append(f"GE*{len(txns)}*{gs_control}~")
    parts.append(f"IEA*{len(groups)}*{isa_control}~")
    return "".join(parts).encode("ascii")


# Segment ordinals of the default smoke message above:
#  1 ISA  2 GS  3 ST  4 BIG  5 SE  6 ST  7 BIG  8 REF  9 SE 10 GE
# 11 GS 12 ST 13 BIG 14 SE 15 GE 16 IEA


# ------------------------------------------------------------------ http i/o


def http_get(path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(API_BASE_URL + path, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError as exc:
        return 0, str(exc).encode()


def http_post_audit(body: bytes) -> tuple[int, dict]:
    request = urllib.request.Request(
        API_BASE_URL + "/api/x12/audit",
        data=body,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read())
        except (ValueError, AttributeError):
            return exc.code, {}
    except OSError as exc:
        return 0, {"transportError": str(exc)}


# -------------------------------------------------------------------- checks


def wait_for_health() -> tuple[bool, str]:
    deadline = time.monotonic() + HEALTH_WAIT_SECONDS
    while time.monotonic() < deadline:
        status, body = http_get("/health")
        if status == 200:
            return True, f"GET /health -> {status} {body.decode(errors='replace')}"
        time.sleep(1)
    return False, f"API at {API_BASE_URL} not healthy within {HEALTH_WAIT_SECONDS}s"


def run_code_tests() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, output


def run_build_check() -> tuple[bool, str]:
    compile_proc = subprocess.run(
        [sys.executable, "-m", "compileall", "-q", "app", "verify.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if compile_proc.returncode != 0:
        return False, compile_proc.stdout + compile_proc.stderr
    import_proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from app.main import app\n"
            "paths = {route.path for route in app.routes}\n"
            "assert '/api/x12/audit' in paths, paths\n"
            "assert '/health' in paths, paths\n"
            "print('ASGI import ok; routes:', sorted(paths))",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    output = (import_proc.stdout + import_proc.stderr).strip()
    return import_proc.returncode == 0, output


def check_valid_envelope() -> tuple[bool, str]:
    payload = build_message()
    status, body = http_post_audit(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()
    ok = (
        status == 200
        and body.get("ok") is True
        and body.get("interchangeControlNumber") == "000000001"
        and body.get("groups") == 2
        and body.get("transactions") == 3
        and body.get("sha256") == expected_sha
    )
    return ok, f"status={status} body={json.dumps(body, sort_keys=True)}"


def _expect_error(
    payload: bytes, status: int, code: str, segment
) -> tuple[bool, str]:
    got_status, body = http_post_audit(payload)
    error = body.get("error") or {}
    ok = (
        got_status == status
        and body.get("ok") is False
        and error.get("code") == code
        and error.get("segment") == segment
    )
    detail = (
        f"want status={status} code={code} segment={segment}; "
        f"got status={got_status} body={json.dumps(body, sort_keys=True)}"
    )
    return ok, detail


def run_smoke_tests() -> list[tuple[str, bool, str]]:
    valid = build_message()
    cases: list[tuple[str, bytes, int, str, object]] = [
        (
            "smoke: SE segment count mismatch located",
            valid.replace(b"SE*3*0001~", b"SE*9*0001~"),
            400,
            "SEGMENT_COUNT_MISMATCH",
            5,
        ),
        (
            "smoke: ST/SE control number mismatch located",
            valid.replace(b"SE*4*0002~", b"SE*4*9999~"),
            400,
            "CONTROL_NUMBER_MISMATCH",
            9,
        ),
        (
            "smoke: IEA group count mismatch located",
            valid.replace(b"IEA*2*", b"IEA*9*"),
            400,
            "GROUP_COUNT_MISMATCH",
            16,
        ),
        (
            "smoke: truncated interchange reported",
            valid[: valid.index(b"IEA*")],
            400,
            "MISSING_IEA",
            15,
        ),
        (
            "smoke: inner envelope error not masked by outer summary",
            valid.replace(b"SE*3*0001~", b"SE*8*0001~").replace(b"IEA*2*", b"IEA*7*"),
            400,
            "SEGMENT_COUNT_MISMATCH",
            5,
        ),
        (
            "smoke: non-ASCII payload rejected",
            valid[:100] + b"\xe9" + valid[101:],
            400,
            "NON_ASCII_PAYLOAD",
            None,
        ),
        (
            "smoke: empty payload rejected",
            b"",
            400,
            "PAYLOAD_EMPTY",
            None,
        ),
        (
            "smoke: oversize payload rejected",
            b"ISA" + b"0" * MAX_PAYLOAD_BYTES,
            413,
            "PAYLOAD_TOO_LARGE",
            None,
        ),
    ]
    results = [("smoke: valid envelope accepted", *check_valid_envelope())]
    for name, payload, status, code, segment in cases:
        ok, detail = _expect_error(payload, status, code, segment)
        results.append((name, ok, detail))
    return results


# ---------------------------------------------------------------------- main


def main() -> int:
    results: list[tuple[str, bool, str]] = []

    ready, detail = wait_for_health()
    results.append(("api readiness (health gate)", ready, detail))
    if ready:
        ok, detail = run_code_tests()
        results.append(("code tests (pytest)", ok, detail))
        ok, detail = run_build_check()
        results.append(("application build check", ok, detail))
        results.extend(run_smoke_tests())
    else:
        results.append(("code tests (pytest)", False, "skipped: API not healthy"))
        results.append(("application build check", False, "skipped: API not healthy"))
        results.append(("http smoke tests", False, "skipped: API not healthy"))

    failed = 0
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        if not ok:
            failed += 1
            if detail:
                tail = "\n".join(detail.rstrip().splitlines()[-40:])
                print(textwrap.indent(tail, "      "))

    print(f"\nverify: {len(results) - failed}/{len(results)} checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
