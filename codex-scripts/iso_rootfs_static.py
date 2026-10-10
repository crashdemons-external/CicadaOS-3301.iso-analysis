#!/usr/bin/env python3
"""Reproduce the static inventory and prime checks for the extracted ISO rootfs."""

import collections
import datetime
import hashlib
import json
import math
import pathlib
import re


REPO = pathlib.Path(__file__).resolve().parents[1]
ROOT = REPO / "output/iso-audit/rootfs"
MANIFEST = REPO / "output/iso-audit/rootfs-manifest.json"
OUT_JSON = REPO / "output/iso-audit/rootfs-static.json"
OUT_MD = REPO / "output/iso-audit/rootfs-static.md"
BASELINE_MTIME = 1356597473


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_prime(n: int) -> bool:
    return n >= 2 and all(n % d for d in range(2, math.isqrt(n) + 1))


entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
by_inode = collections.defaultdict(list)
for entry in entries:
    if entry.get("type") == "regular":
        by_inode[(tuple(entry.get("dev", [])), entry.get("ino"))].append(entry["path"])
hardlinks = [paths for paths in by_inode.values() if len(paths) > 1]

outliers = []
for entry in entries:
    if entry.get("type") == "regular" and entry.get("mtime") != BASELINE_MTIME:
        stamp = datetime.datetime.fromtimestamp(entry["mtime"], datetime.timezone.utc)
        outliers.append({
            "path": entry["path"],
            "mtime_unix": entry["mtime"],
            "mtime_utc": stamp.isoformat(),
            "size": entry.get("size"),
        })

prime_path = ROOT / "usr/local/bin/prime_echo"
prime_text = prime_path.read_text(encoding="utf-8")
primes = [int(x) for x in re.findall(r'echo\s*(?:-n\s*)?"(\d+)\t"', prime_text)]
expected = [n for n in range(2, 3302) if is_prime(n)]
special_pauses = [
    {"line": i + 1, "text": line.strip()}
    for i, line in enumerate(prime_text.splitlines())
    if re.search(r'"(?:1033|3301)\t"', line)
]

custom_names = [
    "usr/local/bin/cicada",
    "usr/local/bin/prime_echo",
    "usr/local/bin/message.txt",
    "usr/local/bin/message.txt.asc",
    "tmp/folly",
    "tmp/wisdom",
]
custom_files = []
for name in custom_names:
    content = (ROOT / name).read_bytes()
    text_preview = None if b"\0" in content else content.decode("utf-8", "replace")[:400]
    custom_files.append({
        "path": name,
        "size": len(content),
        "sha256": sha256(content),
        "text_preview": text_preview,
    })
custom_files[-2]["identical_sha256_to"] = "tmp/wisdom"
custom_files[-1]["identical_sha256_to"] = "tmp/folly"

result = {
    "scope": "static analysis of extracted rootfs; no files executed; symlinks not followed",
    "counts": {
        "manifest_entries": len(entries),
        "regular_files": sum(e.get("type") == "regular" for e in entries),
        "symlinks": sum(e.get("type") == "symlink" for e in entries),
        "hardlink_groups": hardlinks,
    },
    "baseline_mtime": {
        "unix": BASELINE_MTIME,
        "utc": datetime.datetime.fromtimestamp(BASELINE_MTIME, datetime.timezone.utc).isoformat(),
        "regular_file_count": sum(
            e.get("type") == "regular" and e.get("mtime") == BASELINE_MTIME for e in entries
        ),
    },
    "prime_check": {
        "listed_count": len(primes),
        "expected_prime_count_2_to_3301": len(expected),
        "exact_sequence_match": primes == expected,
        "composite_or_invalid_entries": [n for n in primes if not is_prime(n)],
        "omitted_or_extra": {
            "missing": [n for n in expected if n not in primes],
            "extra": [n for n in primes if n not in expected],
        },
        "sleep_0_05_count": len(re.findall(r"sleep \.05", prime_text)),
        "sleep_2_count": len(re.findall(r"sleep 2$", prime_text, re.M)),
        "nominal_explicit_sleep_seconds": 462 * 0.05 + 2 * 2,
        "special_pause_lines": special_pauses,
    },
    "notable_files": custom_files,
    "nonbaseline_regular_file_mtimes": outliers,
    "persistence_and_networking": {
        "initial_autologin": "/sbin/autologin first-run path executes login -f root; root shell then runs cicada",
        "bootlocal_sh": "comment-only placeholder",
        "bootsync_sh": "sets hostname box and backgrounds bootlocal.sh",
        "inittab": "sysinit rcS; tty1 getty -n invokes autologin",
        "default_networking": "ISO command line has loglevel=3 without nodhcp; tc-config starts dhcp.sh in background unless NODHCP is set",
        "puzzle_specific_outbound_networking": "none found in puzzle-specific startup files",
        "generic_network_service_scripts": [
            "etc/init.d/services/tftpd",
            "etc/init.d/services/dhcp",
            "etc/init.d/services/crond",
        ],
    },
    "account_evidence": {
        "root_shell": "/usr/local/bin/cicada",
        "initial_autologin": "/sbin/autologin executes login -f root on first invocation",
        "tc_account": "exists with empty shadow password field and NOPASSWD: ALL sudo; not the initial autologin target",
    },
    "caveats": [
        "The manifest is the authoritative extracted inventory; host extraction can omit empty directories and does not recreate Unix metadata exactly.",
        "All listed symlinks were treated as inert manifest records and not followed.",
        "Prime timing is the sum of requested sleeps; actual display timing also includes shell/process scheduling and terminal output.",
        "Times are archive metadata, not independently authenticated wall-clock creation times.",
    ],
}

OUT_JSON.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _mtime(path: str) -> str:
    entry = next(e for e in entries if e.get("path") == path)
    return datetime.datetime.fromtimestamp(entry["mtime"], datetime.timezone.utc).isoformat()


md = f"""# Static audit of the extracted 3301.iso root filesystem

Scope: read-only inspection of `output/iso-audit/rootfs` and `rootfs-manifest.json`. No extracted code or binary was executed, and symlinks were not followed. No package was used.

## Main findings

- The manifest contains {len(entries):,} entries. {result['baseline_mtime']['regular_file_count']} regular files have the common archive mtime {result['baseline_mtime']['utc']} (Unix {BASELINE_MTIME}). Eight regular files differ: `etc/init.d/tc-config` ({_mtime('etc/init.d/tc-config')}), `etc/passwd` ({_mtime('etc/passwd')}), `usr/local/bin/prime_echo` ({_mtime('usr/local/bin/prime_echo')}), `usr/local/bin/cicada` ({_mtime('usr/local/bin/cicada')}), `usr/local/bin/message.txt.asc` ({_mtime('usr/local/bin/message.txt.asc')}), `usr/local/bin/message.txt` ({_mtime('usr/local/bin/message.txt')}), `tmp/wisdom` ({_mtime('tmp/wisdom')}), and `tmp/folly` ({_mtime('tmp/folly')}). The two December 27 edits precede the puzzle-specific files and should not be grouped with them. Archive mtimes alone do not prove authoring time.
- `etc/inittab` starts `rcS` and configures tty1 getty with `/sbin/autologin`. Its first invocation runs `login -f root`; root's shell is `/usr/local/bin/cicada`. The `tc` account exists with an empty password field and `NOPASSWD: ALL` in `sudoers`, but is not the initial autologin target. `cicada` clears the screen, invokes `prime_echo`, prints `message.txt`, waits 10 seconds, and requests reboot.
- `prime_echo` contains {len(primes)} literal entries and exactly matches every prime from 2 through 3301. It requests 0.05-second sleeps after 462 entries and two-second sleeps at 1033 and 3301, for 27.1 seconds of requested delay before shell and terminal overhead. This differs from the 0.5-second ordinary-delay claim in one documentation source; the script says `.05`.
- `opt/bootsync.sh` sets hostname `box` and backgrounds `opt/bootlocal.sh`, which contains only comments. No regular-file hardlink groups were found. The ISO command line has `loglevel=3` without `nodhcp`, and `tc-config` starts `/etc/init.d/dhcp.sh` in the background unless `NODHCP` is set. Thus default Tiny Core boot attempts DHCP configuration. No puzzle-specific outbound networking command was found. Generic Tiny Core TFTP and cron service scripts are present; presence alone does not establish they are enabled.
- `tmp/folly` and `tmp/wisdom` are each 3,368 bytes and have identical SHA-256 (`{custom_files[-2]['sha256']}`), so they are byte-identical despite different names and mtimes. `message.txt` contains `@1231507051321`, “The key is all around you,” and ends in `3301`. Its adjacent cleartext signature verifies against the local Cicada public key; see `signature-verification.md` for the fingerprint, signer-supplied timestamp, and method.

## Inventory and limitations

There are {len(entries):,} manifest entries and no regular-file inode groups with multiple paths. `etc/skel/.ash_history` is empty. The manifest records `home/tc` but no files below it; the extracted host tree omits that empty directory.

Stock Tiny Core initialization contains generic mount, module, DHCP, and service-management code. This report distinguishes those default OS behaviors from puzzle-specific startup behavior. Static analysis cannot establish all runtime behavior in a VM or authenticate the original ISO source.

Machine-readable details and hashes: `output/iso-audit/rootfs-static.json`. Reproduce with `python codex-scripts/iso_rootfs_static.py`.
"""

with OUT_MD.open("w", encoding="utf-8", newline="\n") as report:
    report.write(md)


print(f"Wrote {OUT_JSON.relative_to(REPO)} and {OUT_MD.relative_to(REPO)}")
