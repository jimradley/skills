#!/usr/bin/env python3
"""
Sensitive-info scanner: walks a folder tree and flags secrets, API keys,
credentials, financial data, and personally identifiable information (PII).

Deterministic detection only — stdlib, no dependencies. Designed to be the
fast, reliable first pass; a human/LLM reviewer adds context afterwards
(free-text names/addresses, false-positive triage, GDPR special categories).

Usage:
    python scan.py [PATH] [--include-all] [--max-bytes N] [--no-color]

Exit code: 0 if nothing CRITICAL/HIGH found, 2 otherwise (handy in CI).
"""
import argparse
import math
import os
import re
import sys

# --- Directories/files that are noise under "smart scope" -------------------
SKIP_DIRS = {
    "node_modules", ".git", ".svn", ".hg", ".vs", ".idea", ".vscode",
    "__pycache__", ".venv", "venv", "env", "packages", "dist", "build",
    "target", "out", ".next", ".nuxt", "coverage", ".gradle", ".terraform",
    "vendor", "bin", "obj", ".pytest_cache", ".mypy_cache", ".tox",
}
SKIP_FILE_SUFFIXES = (
    ".min.js", ".min.css", ".map", "-lock.json", ".lock",
    "package-lock.json", "yarn.lock", "poetry.lock", "Cargo.lock",
)
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".heic", ".heif",
    ".pdf", ".zip", ".gz", ".tar", ".7z", ".rar", ".exe", ".dll", ".so",
    ".dylib", ".bin", ".class", ".jar", ".woff", ".woff2", ".ttf", ".eot",
    ".otf", ".mp3", ".mp4", ".mov", ".avi", ".pyc", ".wasm", ".db", ".sqlite",
}

# --- Severity ordering ------------------------------------------------------
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "REVIEW"]
SEV_RANK = {s: i for i, s in enumerate(SEVS)}

PLACEHOLDER_HINTS = (
    "example", "xxxx", "your", "changeme", "change_me", "placeholder",
    "dummy", "sample", "redacted", "insert", "todo", "fixme", "<", "foo",
    "bar", "abc123", "aaaa", "0000", "1111", "1234567890", "test_key",
    "fake", "mock", "n/a", "none", "null",
)

# Tuned to avoid software-context false positives: "diagnos(is|ed)" not "diagnostics",
# "disability" not "disabled", "ethnic/racial" not bare "race" (race condition, etc.).
GDPR_KEYWORDS = re.compile(
    r"(?i)\b(diagnos(?:is|es|ed)|prescription|medical record|mental health|"
    r"disabilit(?:y|ies)|ethnic\w*|racial|religious belief|sexual orientation|"
    r"biometric|trade union|criminal record|conviction|immigration status|"
    r"pregnan(?:t|cy))\b"
)


def shannon(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if len(v) < 6:
        return True
    return any(h in v for h in PLACEHOLDER_HINTS)


def luhn_ok(num: str) -> bool:
    digits = [int(d) for d in num if d.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def nhs_ok(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if len(d) != 10:
        return False
    total = sum(d[i] * (10 - i) for i in range(9))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == d[9]


def valid_public_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    # skip private / loopback / link-local / multicast / unspecified
    if a in (0, 10, 127) or (a == 192 and b == 168) or (a == 169 and b == 254):
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a >= 224:
        return False
    return True


def redact(value: str) -> str:
    v = value.strip().strip("'\"")
    if len(v) <= 8:
        return v[0] + "*" * (len(v) - 1) if v else ""
    return f"{v[:4]}{'*' * 8}{v[-2:]}"


# --- Detectors --------------------------------------------------------------
# Each: (name, severity, compiled regex, optional validator(match)->bool)
DETECTORS = [
    ("Private key block", "CRITICAL",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"), None),
    ("AWS access key id", "CRITICAL", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    ("Google API key", "CRITICAL", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), None),
    ("GitHub token", "CRITICAL", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), None),
    ("Slack token", "CRITICAL", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), None),
    ("Stripe live key", "CRITICAL", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b"), None),
    ("Anthropic API key", "CRITICAL", re.compile(r"\bsk-ant-[0-9A-Za-z_\-]{20,}\b"), None),
    ("OpenAI API key", "CRITICAL", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), None),
    ("Credentials in URL", "CRITICAL",
     re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/'\"]+:[^\s:/@'\"]+@[^\s'\"]+"), None),
    ("Credit/debit card", "CRITICAL",
     re.compile(r"\b(?:\d[ -]?){13,19}\b"), lambda m: luhn_ok(m.group(0))),
    ("JWT", "HIGH",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), None),
    ("Bearer token", "HIGH",
     re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._\-]{12,}"), None),
    ("Stripe test key", "HIGH", re.compile(r"\b(?:sk|rk)_test_[0-9A-Za-z]{16,}\b"), None),
    ("UK National Insurance no.", "HIGH",
     re.compile(r"\b[ABCEGHJ-PRSTW-Z][ABCEGHJ-NPRSTW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"), None),
    ("UK NHS number", "HIGH",
     re.compile(r"\b\d{3}[ -]?\d{3}[ -]?\d{4}\b"), lambda m: nhs_ok(m.group(0))),
    ("IBAN", "HIGH", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), None),
    ("Email address", "MEDIUM", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), None),
    ("UK mobile number", "MEDIUM",
     re.compile(r"(?:(?:\+44|0044)\s?7\d{3}|\(?07\d{3}\)?)\s?\d{3}\s?\d{3}\b"), None),
    ("UK sort code", "MEDIUM", re.compile(r"\b\d{2}-\d{2}-\d{2}\b"), None),
    ("UK postcode", "MEDIUM",
     re.compile(r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b"), None),
    ("HTTP cookie header (session tokens)", "HIGH",
     re.compile(r"(?i)\b(?:set-)?cookie:\s*\S+=\S+"), None),
    ("Public IP address", "REVIEW",
     re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), lambda m: valid_public_ip(m.group(0))),
]

# Generic "key = value" secret assignment, validated by entropy/placeholder.
ASSIGN_RE = re.compile(
    r"(?i)\b([\w.\-]*(?:api[_-]?key|secret|token|passwd|password|"
    r"client[_-]?secret|access[_-]?key|private[_-]?key|auth)[\w.\-]*)\s*"
    r"[:=]\s*['\"]([^'\"]{6,})['\"]"
)

# Same idea but for UNQUOTED values (cookies, headers, env dumps): name=token
# with no quotes, stopping at separators. Catches e.g. immich_access_token=…,
# RadarrAuth=…, session=… in a Cookie header. Entropy-gated to limit noise.
ASSIGN_UNQUOTED_RE = re.compile(
    r"(?i)\b([\w.\-]*(?:api[_-]?key|secret|token|passwd|password|"
    r"access[_-]?key|auth|session|sid|csrf|bearer)[\w.\-]*)\s*[:=]\s*"
    r"([A-Za-z0-9._\-+/%]{12,})"
)


class Finding:
    __slots__ = ("severity", "kind", "relpath", "lineno", "redacted")

    def __init__(self, severity, kind, relpath, lineno, redacted):
        self.severity = severity
        self.kind = kind
        self.relpath = relpath
        self.lineno = lineno
        self.redacted = redacted


def scan_line(line: str, relpath: str, lineno: int, out: list):
    # Long single-line files (error dumps, minified JSON, logs) must still be
    # scanned fully — scan in overlapping windows so we never silently drop the
    # tail of a line, while bounding regex work per call.
    if len(line) <= 16000:
        _scan_segment(line, relpath, lineno, out)
        return
    step, overlap = 16000, 512
    pos = 0
    while pos < len(line):
        _scan_segment(line[pos:pos + step + overlap], relpath, lineno, out)
        pos += step


def _scan_segment(line: str, relpath: str, lineno: int, out: list):
    for name, sev, rx, validator in DETECTORS:
        for m in rx.finditer(line):
            if validator and not validator(m):
                continue
            out.append(Finding(sev, name, relpath, lineno, redact(m.group(0))))

    for m in ASSIGN_RE.finditer(line):
        key, value = m.group(1), m.group(2)
        if looks_like_placeholder(value):
            continue
        sev = "HIGH" if shannon(value) >= 3.0 or len(value) >= 24 else "REVIEW"
        out.append(Finding(sev, f"Secret assignment ({key})", relpath, lineno, redact(value)))

    for m in ASSIGN_UNQUOTED_RE.finditer(line):
        key, value = m.group(1), m.group(2)
        if looks_like_placeholder(value) or shannon(value) < 3.0:
            continue
        out.append(Finding("HIGH", f"Token/credential ({key})", relpath, lineno, redact(value)))

    if GDPR_KEYWORDS.search(line):
        out.append(Finding("REVIEW", "GDPR special-category keyword", relpath, lineno,
                           GDPR_KEYWORDS.search(line).group(0)))


def is_probably_binary(path: str) -> bool:
    if os.path.splitext(path)[1].lower() in BINARY_EXTS:
        return True
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def main():
    ap = argparse.ArgumentParser(description="Scan a folder for sensitive info.")
    ap.add_argument("path", nargs="?", default=".", help="folder to scan (default: cwd)")
    ap.add_argument("--include-all", action="store_true",
                    help="do not skip vendor/build/VCS directories")
    ap.add_argument("--max-bytes", type=int, default=2_000_000,
                    help="skip files larger than this (default 2MB)")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    # Windows consoles default to cp1252 and choke on the report's emoji/box glyphs.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    scanned = skipped_dirs = skipped_files = 0
    flagged_files = set()

    for dirpath, dirnames, filenames in os.walk(root):
        if not args.include_all:
            keep = [d for d in dirnames if d not in SKIP_DIRS]
            skipped_dirs += len(dirnames) - len(keep)
            dirnames[:] = keep
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if any(fn.endswith(s) for s in SKIP_FILE_SUFFIXES):
                skipped_files += 1
                continue
            try:
                if os.path.getsize(full) > args.max_bytes:
                    skipped_files += 1
                    continue
            except OSError:
                continue
            if is_probably_binary(full):
                skipped_files += 1
                continue
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as f:
                    before = len(findings)
                    for i, line in enumerate(f, 1):
                        scan_line(line, rel, i, findings)
                    if len(findings) > before:
                        flagged_files.add(rel)
                scanned += 1
            except OSError:
                skipped_files += 1

    # filenames that are themselves a red flag
    for dirpath, dirnames, filenames in os.walk(root):
        if not args.include_all:
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            low = fn.lower()
            if low == ".env" or low.startswith(".env.") or low in (
                "id_rsa", "id_dsa", "id_ecdsa", ".npmrc", ".pgpass",
                "credentials", "credentials.json", "secrets.json", ".htpasswd",
            ):
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                findings.append(Finding("HIGH", "Secret-bearing file (by name)", rel, 0, fn))
                flagged_files.add(rel)

    # De-duplicate (overlapping line windows / multiple detectors can repeat a hit).
    seen, deduped = set(), []
    for f in findings:
        key = (f.severity, f.kind, f.relpath, f.lineno, f.redacted)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    findings = deduped

    print_report(root, findings, scanned, skipped_dirs, skipped_files,
                 flagged_files, color=not args.no_color)

    worst = min((SEV_RANK[f.severity] for f in findings), default=99)
    return 2 if worst <= SEV_RANK["HIGH"] else 0


COLORS = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[96m",
          "REVIEW": "\033[90m", "RESET": "\033[0m", "BOLD": "\033[1m"}


def print_report(root, findings, scanned, skipped_dirs, skipped_files,
                 flagged_files, color):
    def c(key, text):
        return f"{COLORS[key]}{text}{COLORS['RESET']}" if color else text

    print()
    print(c("BOLD", f"🔒 Sensitive-info scan — {root}"))
    print(f"   scanned {scanned} text files · skipped {skipped_files} files "
          f"and {skipped_dirs} vendor/build dirs")
    print()

    if not findings:
        print(c("BOLD", "✅ No sensitive data detected by the pattern scan."))
        print("   (Still worth a human glance for free-text names/addresses.)")
        return

    counts = {s: 0 for s in SEVS}
    by_sev = {s: [] for s in SEVS}
    for f in findings:
        by_sev[f.severity].append(f)
        counts[f.severity] += 1

    for sev in SEVS:
        rows = by_sev[sev]
        if not rows:
            continue
        print(c(sev, c("BOLD", f"{sev}  ({len(rows)})")))
        rows.sort(key=lambda r: (r.relpath, r.lineno))
        for r in rows[:200]:
            loc = f"{r.relpath}:{r.lineno}" if r.lineno else r.relpath
            print(f"  {c(sev, '•')} {loc}".ljust(52) + f"[{r.kind}]  {r.redacted}")
        if len(rows) > 200:
            print(f"    … and {len(rows) - 200} more")
        print()

    summary = " · ".join(f"{counts[s]} {s.lower()}" for s in SEVS if counts[s])
    print(c("BOLD", f"Summary: {summary}  across {len(flagged_files)} file(s)."))


if __name__ == "__main__":
    sys.exit(main())
