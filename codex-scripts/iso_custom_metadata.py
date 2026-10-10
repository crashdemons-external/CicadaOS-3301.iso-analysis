#!/usr/bin/env python3
"""Export cpio-manifest metadata for puzzle-associated ISO rootfs files."""

import csv
import datetime
import json
import pathlib
import stat


REPO = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = REPO / "output/iso-audit/rootfs-manifest.json"
ROOTFS = REPO / "output/iso-audit/rootfs"
OUTDIR = REPO / "output/iso-audit"

TARGETS = {
    "tmp/folly": "puzzle artifact",
    "tmp/wisdom": "puzzle artifact",
    "tmp/aberr": "related empty temporary file; authorship unproven",
    "usr/local/bin/cicada": "custom boot script",
    "usr/local/bin/prime_echo": "custom prime display script",
    "usr/local/bin/message.txt": "puzzle message",
    "usr/local/bin/message.txt.asc": "signed puzzle message",
    "etc/passwd": "likely modified system account file (classification inferred)",
    "etc/init.d/tc-config": "likely modified system startup file (classification inferred)",
    "tmp": "related directory",
    "usr/local/bin": "related directory",
    "sbin/autologin": "related stock-date login script; modification classification inferred",
}


def id_name_maps():
    users, groups = {}, {}
    passwd = ROOTFS / "etc/passwd"
    group = ROOTFS / "etc/group"
    for line in passwd.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2].isdigit():
            users.setdefault(int(fields[2]), []).append(fields[0])
    for line in group.read_text(encoding="utf-8", errors="replace").splitlines():
        fields = line.split(":")
        if len(fields) > 2 and fields[2].isdigit():
            groups.setdefault(int(fields[2]), []).append(fields[0])
    return users, groups


def names(mapping, numeric_id):
    found = mapping.get(numeric_id, [])
    return ",".join(found) if found else "unmapped"


def normalized_entry(entry, users, groups):
    mode_text = entry.get("mode", "0o0")
    mode = int(mode_text, 8)
    dev = entry.get("dev", [None, None])
    rdev = entry.get("rdev", [None, None])
    stamp = entry.get("mtime")
    return {
        "path": entry["path"],
        "type": entry.get("type"),
        "mode_manifest": mode_text,
        "mode_octal": format(mode, "06o"),
        "file_type_bits_octal": format(stat.S_IFMT(mode), "06o"),
        "permissions": stat.filemode(mode),
        "uid": entry.get("uid"),
        "uid_names_from_passwd": names(users, entry.get("uid")),
        "gid": entry.get("gid"),
        "gid_names_from_group": names(groups, entry.get("gid")),
        "nlink": entry.get("nlink"),
        "mtime_unix": stamp,
        "mtime_utc": datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).isoformat() if stamp is not None else None,
        "size": entry.get("size"),
        "sha256": entry.get("sha256"),
        "devmajor": dev[0] if len(dev) > 0 else None,
        "devminor": dev[1] if len(dev) > 1 else None,
        "rdevmajor": rdev[0] if len(rdev) > 0 else None,
        "rdevminor": rdev[1] if len(rdev) > 1 else None,
        "cpio_inode": entry.get("ino"),
        "header_offset": entry.get("header_offset"),
        "data_offset": entry.get("data_offset"),
        "md5_manifest": entry.get("md5"),
        "sha1_manifest": entry.get("sha1"),
        "cpio_format": entry.get("format"),
        "name_size_with_nul": entry.get("name_size_with_nul"),
        "checksum_field": entry.get("checksum_field"),
        "raw_header_hex": entry.get("header_hex"),
    }


entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
users, groups = id_name_maps()
by_path = {entry["path"]: entry for entry in entries}
missing = sorted(set(TARGETS) - set(by_path))
if missing:
    raise SystemExit(f"Manifest is missing requested paths: {missing}")

records = []
for path, classification in TARGETS.items():
    row = normalized_entry(by_path[path], users, groups)
    row["classification"] = classification
    records.append(row)

# Include inode-neighbor context at +/- three numeric inode values for each target.
ordered = sorted((e for e in entries if isinstance(e.get("ino"), int)), key=lambda e: (e["ino"], e["path"]))
neighbor_context = {}
for path in TARGETS:
    inode = by_path[path].get("ino")
    nearby = [e for e in ordered if abs(e["ino"] - inode) <= 3]
    neighbor_context[path] = [normalized_entry(e, users, groups) for e in nearby]

inode_groups = {}
for entry in entries:
    inode_groups.setdefault(entry.get("ino"), []).append(entry["path"])
duplicate_inodes = {str(i): paths for i, paths in inode_groups.items() if len(paths) > 1}
mode_counts = {}
type_counts = {}
nlink_counts = {}
dev_counts = {}
for entry in entries:
    mode_counts[entry.get("mode")] = mode_counts.get(entry.get("mode"), 0) + 1
    type_counts[entry.get("type")] = type_counts.get(entry.get("type"), 0) + 1
    nlink_counts[entry.get("nlink")] = nlink_counts.get(entry.get("nlink"), 0) + 1
    dev = tuple(entry.get("dev", []))
    dev_counts[str(dev)] = dev_counts.get(str(dev), 0) + 1

result = {
    "scope": "selected extracted rootfs cpio manifest records; metadata is archive-level evidence",
    "identity_caveat": "These are inode values recorded in the cpio archive. They are not proof of persistent source filesystem inode identities and may have been renumbered during image construction.",
    "targets": records,
    "neighbor_records_by_target_inode_plus_minus_3": neighbor_context,
    "manifest_anomalies_and_distributions": {
        "manifest_entries": len(entries),
        "zero_inode_paths": [e["path"] for e in entries if e.get("ino") == 0],
        "duplicate_inode_groups": duplicate_inodes,
        "hardlinked_regular_file_groups_by_inode": {
            str(i): paths for i, paths in inode_groups.items()
            if len(paths) > 1 and all(by_path[p].get("type") == "regular" for p in paths)
        },
        "type_counts": type_counts,
        "nlink_counts": nlink_counts,
        "mode_counts": mode_counts,
        "device_pair_counts": dev_counts,
        "empty_regular_files": [e["path"] for e in entries if e.get("type") == "regular" and e.get("size") == 0],
        "symlink_records": [
            {"path": e["path"], "target": e.get("target"), "ino": e.get("ino"), "nlink": e.get("nlink")}
            for e in entries if e.get("type") == "symlink"
        ],
    },
    "interpretation_notes": [
        "Ownership names are resolved from the archived /etc/passwd and /etc/group contents; unmapped numeric IDs remain numeric evidence.",
        "The eight listed files outside the common rootfs mtime baseline are metadata outliers, not authenticated creation dates.",
        "tmp/wisdom and tmp/folly have identical SHA-256 values; their mtimes differ by 88 seconds.",
        "sbin/autologin has the common baseline mtime even though its observed first-login behavior is relevant; inclusion here does not prove the file was changed from its upstream version.",
    ],
}

json_path = OUTDIR / "custom-file-metadata.json"
json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

csv_path = OUTDIR / "custom-file-metadata.csv"
columns = list(records[0].keys())
with csv_path.open("w", encoding="utf-8", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(records)

meta = result["manifest_anomalies_and_distributions"]
md = f"""# Custom and related rootfs file metadata

Source: `{MANIFEST.relative_to(REPO).as_posix()}`. The table records cpio manifest fields for the six puzzle-associated files, two likely system-file modifications, related paths including empty `/tmp/aberr`, related directories, and `/sbin/autologin` for boot context. The system-file classifications are inferred from their role and nonbaseline timestamps; the autologin and `/tmp/aberr` classifications are explicitly unproven.

| Path | Classification | Cpio inode | Mode | UID:GID | Nlink | Size | Mtime UTC | SHA-256 | Data offset |
|---|---|---:|---|---|---:|---:|---|---|---:|
"""
for row in records:
    md += f"| `{row['path']}` | {row['classification']} | {row['cpio_inode']} | `{row['permissions']} ({row['mode_octal']})` | {row['uid']}:{row['gid']} ({row['uid_names_from_passwd']}:{row['gid_names_from_group']}) | {row['nlink']} | {row['size']} | {row['mtime_utc']} | `{row['sha256'] or ''}` | {row['data_offset']} |\n"

md += f"""
## Metadata observations

- The two temporary puzzle files each have size 3,368 bytes, mode `100644`, UID:GID `0:0` (root:root), one link, device pair `8:1`, and byte-identical SHA-256. `wisdom` has mtime {by_path['tmp/wisdom']['mtime']} ({records[1]['mtime_utc']}); `folly` has mtime {by_path['tmp/folly']['mtime']} ({records[0]['mtime_utc']}), an 88-second difference.
- The four `/usr/local/bin` puzzle files have UID:GID `0:0`, one link, and device pair `8:1`. `cicada` and `prime_echo` are executable (`100755`); message files are `100644`.
- `etc/passwd` and `etc/init.d/tc-config` have numeric ownership root:staff (`0:50`) and differ from the common rootfs mtime. This supports treating them as likely adjusted system files, but their cpio metadata alone does not prove who changed them or when.
- `/sbin/autologin` is executable and records root:staff ownership, one link, device pair `8:1`, and the common rootfs timestamp. It is included because its first-login behavior is operationally relevant; the metadata does not establish that it was custom-authored.
- The manifest has {meta['manifest_entries']} entries, {len(meta['zero_inode_paths'])} zero-inode path (`TRAILER!!!`, the cpio end marker), {len(meta['duplicate_inode_groups'])} duplicate-inode groups, and {len(meta['hardlinked_regular_file_groups_by_inode'])} groups of multiple regular paths sharing an inode. It records {len(meta['empty_regular_files'])} zero-length regular files, including `/tmp/aberr`; the JSON lists all of them. Device pair counts are summarized there as well. These are properties of this archive manifest, not a reconstruction of original on-disk filesystem identities.

The “neighbor records” section in the JSON includes paths with cpio inode values within +/- 3 of each target inode. These values may be useful for spotting packing or numbering patterns; proximity alone does not show directory adjacency, authorship, or chronology.

Reproduce the JSON, CSV, and this UTF-8 report with `python codex-scripts/iso_custom_metadata.py`. No extracted code or binary is executed.
"""

md_path = OUTDIR / "custom-file-metadata.md"
with md_path.open("w", encoding="utf-8", newline="\n") as handle:
    handle.write(md)

print(f"Wrote {json_path.relative_to(REPO)}, {csv_path.relative_to(REPO)}, and {md_path.relative_to(REPO)}")
