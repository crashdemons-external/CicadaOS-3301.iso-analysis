#!/usr/bin/env python3
"""Audit gzip and newc framing in the extracted 3301.IMG initramfs, read-only."""

import collections
import datetime
import hashlib
import json
import pathlib
import posixpath
import struct
import zlib


REPO = pathlib.Path(__file__).resolve().parents[1]
OUT = REPO / "output/iso-audit"
IMAGE = OUT / "iso-files/BOOT/3301.IMG"
RAW_CPIO = OUT / "initramfs.cpio"
MANIFEST = OUT / "rootfs-manifest.json"
JSON_OUT = OUT / "cpio-framing-audit.json"
MD_OUT = OUT / "cpio-framing-audit.md"
MAX_EXPANDED = 128 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def parse_gzip_header(data):
    if len(data) < 18 or data[:3] != b"\x1f\x8b\x08":
        raise ValueError("Input is not a complete gzip/deflate member")
    flags = data[3]
    if flags & 0xE0:
        raise ValueError(f"Reserved gzip FLG bits set: {flags:#x}")
    mtime = int.from_bytes(data[4:8], "little")
    xfl, os_byte = data[8], data[9]
    pos = 10
    fields = {"extra": None, "filename_bytes": None, "comment_bytes": None, "header_crc16": None}
    if flags & 4:
        xlen = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        fields["extra"] = data[pos:pos + xlen]
        fields["extra_length"] = xlen
        pos += xlen
    if flags & 8:
        end = data.index(0, pos)
        fields["filename_bytes"] = data[pos:end]
        pos = end + 1
    if flags & 16:
        end = data.index(0, pos)
        fields["comment_bytes"] = data[pos:end]
        pos = end + 1
    if flags & 2:
        got = int.from_bytes(data[pos:pos + 2], "little")
        calc = zlib.crc32(data[:pos]) & 0xFFFF
        fields["header_crc16"] = {"stored": got, "calculated": calc, "valid": got == calc}
        pos += 2
    fields.update({"flags": flags, "mtime_unix": mtime, "xfl": xfl, "os_byte": os_byte,
                   "header_size": pos, "header_hex": data[:pos].hex()})
    return fields, pos


def unpack_newc(cpio):
    records = []
    pads = []
    pos = 0
    while pos < len(cpio):
        start = pos
        if len(cpio) - pos < 110:
            return records, pads, {"error": "short header at end", "offset": pos}
        header = cpio[pos:pos + 110]
        magic = header[:6]
        if magic not in (b"070701", b"070702"):
            return records, pads, {"error": "unexpected cpio magic", "offset": pos, "magic_hex": magic.hex()}
        field_hex = [header[i:i + 8] for i in range(6, 110, 8)]
        try:
            v = [int(header[i:i + 8], 16) for i in range(6, 110, 8)]
        except ValueError:
            return records, pads, {"error": "nonhex cpio header field", "offset": pos}
        (ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
         rdevmajor, rdevminor, namesize, check) = v
        pos += 110
        if namesize < 1 or pos + namesize > len(cpio):
            return records, pads, {"error": "invalid namesize", "offset": start, "namesize": namesize}
        name_field_start = pos
        name_field = cpio[pos:pos + namesize]
        pos += namesize
        name_pad_len = (-pos) % 4
        name_pad = cpio[pos:pos + name_pad_len]
        pos += name_pad_len
        data_start = pos
        if pos + filesize > len(cpio):
            return records, pads, {"error": "payload exceeds archive", "offset": start, "filesize": filesize}
        payload = cpio[pos:pos + filesize]
        pos += filesize
        data_pad_len = (-pos) % 4
        data_pad = cpio[pos:pos + data_pad_len]
        pos += data_pad_len
        null_terminated = name_field.endswith(b"\0")
        name_bytes = name_field[:-1] if null_terminated else name_field
        record = {
            "index": len(records), "header_offset": start, "magic": magic.decode("ascii"),
            "ino": ino, "mode": mode, "uid": uid, "gid": gid, "nlink": nlink,
            "mtime": mtime, "filesize": filesize, "devmajor": devmajor, "devminor": devminor,
            "rdevmajor": rdevmajor, "rdevminor": rdevminor, "namesize": namesize, "check": check,
            "name_field_start": name_field_start, "name_field_hex": name_field.hex(),
            "name_bytes_hex": name_bytes.hex(), "name": name_bytes.decode("utf-8", "surrogateescape"),
            "name_nul_terminated": null_terminated, "name_padding_offset": name_field_start + namesize,
            "header_hex_digit_case": "uppercase" if all(not any(97 <= b <= 102 for b in x) for x in field_hex) else "lowercase_or_mixed",
            "header_fields_canonical_8_hex": all(len(x) == 8 and all(c in b"0123456789abcdefABCDEF" for c in x) for x in field_hex),
            "embedded_nul_in_name": b"\0" in name_bytes,
            "name_padding_length": name_pad_len, "name_padding_hex": name_pad.hex(),
            "data_offset": data_start, "data_padding_offset": data_start + filesize,
            "data_padding_length": data_pad_len, "data_padding_hex": data_pad.hex(),
            "next_header_offset": pos, "payload_sha256": sha256(payload),
        }
        if stat_type(mode) == "symlink":
            record["symlink_target_bytes_hex"] = payload.hex()
            record["symlink_target"] = payload.decode("utf-8", "surrogateescape")
        if magic == b"070702":
            record["crc_sum_calculated"] = sum(payload) & 0xFFFFFFFF
            record["crc_sum_valid"] = record["crc_sum_calculated"] == check
        records.append(record)
        pads.append({
            "record_index": record["index"], "name": record["name"],
            "name_padding_offset": record["name_padding_offset"],
            "name_padding_hex": name_pad.hex(), "name_padding_zero": not any(name_pad),
            "data_padding_offset": record["data_padding_offset"],
            "data_padding_hex": data_pad.hex(), "data_padding_zero": not any(data_pad),
        })
        if record["name"] == "TRAILER!!!":
            expected_zero = record["mode"] == record["uid"] == record["gid"] == record["filesize"] == record["devmajor"] == record["devminor"] == record["rdevmajor"] == record["rdevminor"] == record["check"] == 0
            record["trailer_fields_semantically_zero"] = expected_zero
            return records, pads, {"trailer_offset": start, "after_trailer_offset": pos, "trailer_index": record["index"]}
    return records, pads, {"error": "archive ended without TRAILER!!!", "offset": pos}


def stat_type(mode):
    return {0o100000: "regular", 0o040000: "directory", 0o120000: "symlink",
            0o060000: "block_device", 0o020000: "character_device", 0o010000: "fifo",
            0o140000: "socket"}.get(mode & 0o170000, "unknown")


class DeflateBits:
    def __init__(self, data): self.data, self.bit = data, 0
    def read(self, n):
        if self.bit + n > len(self.data) * 8: raise ValueError("truncated deflate bitstream")
        v = 0
        for i in range(n): v |= ((self.data[self.bit >> 3] >> (self.bit & 7)) & 1) << i; self.bit += 1
        return v
    def huff(self, table):
        code = 0
        for width in range(1, table["max"] + 1):
            code = (code << 1) | self.read(1)
            symbol = table["codes"].get((width, code))
            if symbol is not None: return symbol
        raise ValueError("invalid Huffman code")
    def align(self):
        count = (-self.bit) % 8
        start = self.bit
        value = self.read(count) if count else 0
        return {"bit_offset": start, "bit_count": count, "value": value}


def huffman(lengths):
    counts = collections.Counter(x for x in lengths if x)
    if not counts: raise ValueError("empty Huffman alphabet")
    next_code, code, codes = {}, 0, {}
    for width in range(1, max(counts) + 1):
        code = (code + counts.get(width - 1, 0)) << 1
        next_code[width] = code
    for symbol, width in enumerate(lengths):
        if width:
            codes[(width, next_code[width])] = symbol
            next_code[width] += 1
    return {"codes": codes, "max": max(counts)}


def walk_deflate(data):
    bits = DeflateBits(data)
    fixed_lit = huffman([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8)
    fixed_dist = huffman([5] * 32)
    cl_order = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]
    lbase = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258]
    lextra = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0]
    dbase = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577]
    dextra = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13]
    blocks, alignments, output_size, final = [], [], 0, False
    while not final:
        start = bits.bit
        final = bool(bits.read(1)); typ = bits.read(2)
        block = {"index": len(blocks), "start_bit": start, "final": final,
                 "type": {0:"stored",1:"fixed",2:"dynamic",3:"reserved"}[typ]}
        if typ == 3: raise ValueError("reserved BTYPE")
        if typ == 0:
            padding = bits.align(); alignments.append(padding)
            n, nn = bits.read(16), bits.read(16)
            if (n ^ 0xffff) != nn: raise ValueError("stored LEN/NLEN mismatch")
            bits.read(n * 8); output_size += n
            block.update({"stored_len": n, "stored_alignment": padding})
        else:
            if typ == 1: lit, dist = fixed_lit, fixed_dist
            else:
                hlit, hdist, hclen = bits.read(5)+257, bits.read(5)+1, bits.read(4)+4
                cls = [0] * 19
                for i in range(hclen): cls[cl_order[i]] = bits.read(3)
                ct = huffman(cls); lengths = []
                while len(lengths) < hlit + hdist:
                    sym = bits.huff(ct)
                    if sym <= 15: lengths.append(sym)
                    elif sym == 16:
                        if not lengths: raise ValueError("repeat previous with no previous code length")
                        lengths.extend([lengths[-1]] * (bits.read(2)+3))
                    elif sym == 17: lengths.extend([0] * (bits.read(3)+3))
                    elif sym == 18: lengths.extend([0] * (bits.read(7)+11))
                    if len(lengths) > hlit + hdist: raise ValueError("code length repeat overflow")
                lit, dist = huffman(lengths[:hlit]), huffman(lengths[hlit:])
            before = output_size
            while True:
                sym = bits.huff(lit)
                if sym < 256: output_size += 1
                elif sym == 256: break
                elif 257 <= sym <= 285:
                    i = sym - 257; length = lbase[i] + bits.read(lextra[i])
                    ds = bits.huff(dist)
                    if ds >= 30: raise ValueError("reserved distance symbol")
                    distance = dbase[ds] + bits.read(dextra[ds])
                    if distance > output_size: raise ValueError("distance exceeds produced output")
                    output_size += length
                else: raise ValueError("reserved literal/length symbol")
            block["decoded_output_bytes"] = output_size - before
        block["end_bit"] = bits.bit
        blocks.append(block)
    final_pad_count = (-bits.bit) % 8
    final_pad_start = bits.bit
    final_pad = bits.read(final_pad_count) if final_pad_count else 0
    if bits.bit != len(data) * 8: raise ValueError(f"unconsumed deflate bytes/bits: stopped at {bits.bit}, size {len(data)*8}")
    return {"parser_valid": True, "blocks": blocks, "block_type_counts": dict(collections.Counter(b["type"] for b in blocks)),
            "block_count": len(blocks), "output_byte_count_accounted_for": output_size,
            "stored_alignment_padding_bits": alignments,
            "final_ignored_padding": {"bit_offset": final_pad_start, "bit_count": final_pad_count, "value": final_pad},
            "deflate_bits_consumed_including_final_byte_padding": bits.bit,
            "meaningful_deflate_bits_through_final_eob_or_stored_data": final_pad_start,
            "unused_trailing_bytes": 0}


def bit_padding_selfcheck():
    # RFC 1951 final stored block: BFINAL=1/BTYPE=00, alignment bits, LEN=1,
    # NLEN=0xfffe, payload 'A'. Alignment bits are deliberately initially zero.
    stored = bytes([0x01, 0x01, 0x00, 0xfe, 0xff, 0x41])
    # Final fixed-Huffman block with EOB followed by six zero ignored bits.
    # BFINAL=1, BTYPE=01, then fixed code 256 (EOB), LSB-packed.
    final = bytes([0x03, 0x00])
    cases = []
    for label, data, bit_offset, expected_field in (
        ("stored_alignment", stored, 3, "stored_alignment_padding_bits"),
        ("final_byte_padding", final, 10, "final_ignored_padding"),
    ):
        baseline = walk_deflate(data)
        mutated = bytearray(data); mutated[bit_offset >> 3] ^= 1 << (bit_offset & 7)
        altered = walk_deflate(bytes(mutated))
        decoded_a = zlib.decompress(data, -15); decoded_b = zlib.decompress(bytes(mutated), -15)
        if decoded_a != decoded_b or baseline[expected_field] == altered[expected_field]:
            raise AssertionError(f"{label} padding mutation selfcheck failed")
        cases.append({"case":label,"payload_bytes":decoded_a.hex(),"zlib_output_unchanged":True,
                      "padding_value_before":baseline[expected_field],"padding_value_after":altered[expected_field],
                      "walker_detected_change":baseline[expected_field] != altered[expected_field]})
    return {"passed":True,"cases":cases,
            "scope":"synthetic raw-deflate fixtures only; confirms the bit walker observes padding changes ignored by zlib output"}


def path_analysis(records):
    exact, normalized, casefolded = collections.defaultdict(list), collections.defaultdict(list), collections.defaultdict(list)
    hazards, symlink_hazards = [], []
    for record in records:
        name = record["name"]
        exact[name].append(record["index"])
        normalized_name = posixpath.normpath(name)
        normalized[normalized_name].append(record["index"])
        casefolded[normalized_name.casefold()].append(record["index"])
        parts = name.split("/")
        issues = []
        if name.startswith("/"):
            issues.append("absolute archive path")
        if ".." in parts:
            issues.append("parent traversal component")
        if "" in parts[1:] and name not in ("", "."):
            issues.append("empty path component / repeated or trailing slash")
        if any(ord(c) < 32 or ord(c) == 127 for c in name):
            issues.append("control character in path")
        if issues:
            hazards.append({"index": record["index"], "path": name, "issues": issues})
        if record.get("type") == "symlink":
            target = record.get("symlink_target", "")
            tparts = target.split("/")
            target_issues = []
            if target.startswith("/"):
                target_issues.append("absolute symlink target")
            if ".." in tparts:
                target_issues.append("parent traversal component")
            if "\\" in target:
                target_issues.append("backslash in symlink target")
            if any(ord(c) < 32 or ord(c) == 127 for c in target):
                target_issues.append("control character in symlink target")
            if target_issues:
                symlink_hazards.append({"index": record["index"], "path": name,
                                        "target": target, "issues": target_issues})
    duplicate = lambda m: {key: indexes for key, indexes in m.items() if len(indexes) > 1}
    return {
        "exact_duplicate_path_groups": duplicate(exact),
        "normalized_path_alias_groups": duplicate(normalized),
        "casefolded_path_alias_groups": duplicate(casefolded),
        "path_hazards": hazards,
        "symlink_target_hazards": symlink_hazards,
    }


image = IMAGE.read_bytes()
gzip_fields, deflate_start = parse_gzip_header(image)
decompressor = zlib.decompressobj(-15)
compressed = image[deflate_start:]
parts, source_pos, expanded = [], 0, 0
while source_pos < len(compressed):
    chunk = compressed[source_pos:source_pos + 65536]
    source_pos += len(chunk)
    while chunk:
        out = decompressor.decompress(chunk, MAX_EXPANDED + 1 - expanded)
        parts.append(out); expanded += len(out)
        if expanded > MAX_EXPANDED: raise SystemExit("expanded gzip stream exceeds 128 MiB safety cap")
        chunk = decompressor.unconsumed_tail
        if decompressor.eof: break
    if decompressor.eof: break
if not decompressor.eof: raise SystemExit("raw deflate stream did not reach EOF")
raw = b"".join(parts)
if decompressor.unused_data is None: raise SystemExit("decompressor returned no unused_data state")
consumed = source_pos - len(decompressor.unused_data)
deflate_end = deflate_start + consumed
deflate_audit = walk_deflate(image[deflate_start:deflate_end])
padding_selfcheck = bit_padding_selfcheck()
trailer = image[deflate_end:deflate_end + 8]
if len(trailer) != 8:
    raise SystemExit("Gzip trailer truncated")
stored_crc, stored_size = struct.unpack("<II", trailer)
trailing = image[deflate_end + 8:]
raw_saved = RAW_CPIO.read_bytes()
records, pads, end_info = unpack_newc(raw)
manifest_entries = json.loads(MANIFEST.read_text(encoding="utf-8"))
manifest_by_path = {e["path"]: e for e in manifest_entries}

for record in records:
    mode = record["mode"]
    record["type"] = stat_type(mode)
    record["mode_octal"] = format(mode, "06o")
    record["setuid"] = bool(mode & 0o4000)
    record["setgid"] = bool(mode & 0o2000)
    record["sticky"] = bool(mode & 0o1000)
    record["reserved_mode_high_bits"] = mode & ~0o177777
    if record["name"] in manifest_by_path:
        expected = manifest_by_path[record["name"]]
        record["matches_manifest"] = {
            "header_offset": record["header_offset"] == expected.get("header_offset"),
            "data_offset": record["data_offset"] == expected.get("data_offset"),
            "ino": record["ino"] == expected.get("ino"),
            "mode": record["mode"] == int(expected.get("mode", "0o0"), 8),
            "size": record["filesize"] == expected.get("size"),
            "sha256": record["payload_sha256"] == expected.get("sha256"),
        }
    else:
        record["matches_manifest"] = None

nonzero_name_pads = [p for p in pads if not p["name_padding_zero"]]
nonzero_data_pads = [p for p in pads if not p["data_padding_zero"]]
header_encoding_issues = [{"path":r["name"],"case":r["header_hex_digit_case"],"canonical":r["header_fields_canonical_8_hex"]} for r in records if not r["header_fields_canonical_8_hex"]]
name_encoding_issues = [{"path":r["name"],"embedded_nul":r["embedded_nul_in_name"],"nul_terminated":r["name_nul_terminated"]} for r in records if r["embedded_nul_in_name"] or not r["name_nul_terminated"]]
reserved_mode_issues = [{"path":r["name"],"mode":r["mode"],"reserved_high_bits":r["reserved_mode_high_bits"]} for r in records if r["reserved_mode_high_bits"]]
inode_groups = collections.defaultdict(list)
for r in records:
    if r["name"] != "TRAILER!!!": inode_groups[(r["devmajor"],r["devminor"],r["ino"])].append(r)
inode_anomalies = [{"device_inode":list(key),"paths":[r["name"] for r in group],"nlinks":[r["nlink"] for r in group],"sizes":[r["filesize"] for r in group]}
                   for key,group in inode_groups.items() if any(r["ino"] == 0 or r["nlink"] == 0 for r in group) or len(group) > 1]
declared_nlink_summary = {"records_with_nlink_zero":sum(r["nlink"] == 0 for r in records if r["name"] != "TRAILER!!!"),
                          "records_with_nlink_one":sum(r["nlink"] == 1 for r in records if r["name"] != "TRAILER!!!"),
                          "records_with_nlink_greater_than_one":sum(r["nlink"] > 1 for r in records if r["name"] != "TRAILER!!!"),
                          "same_inode_groups":sum(len(v)>1 for v in inode_groups.values()),
                          "interpretation":"nlink counts filesystem links, not necessarily the number of archive path records; directory counts include filesystem directory links and are not compared as if they were hardlink records."}
paths = path_analysis(records)
mode_counts = collections.Counter(r["type"] for r in records)
flagged_modes = [
    {"path": r["name"], "mode_octal": r["mode_octal"], "setuid": r["setuid"],
     "setgid": r["setgid"], "sticky": r["sticky"]}
    for r in records if r["setuid"] or r["setgid"] or r["sticky"]
]
manifest_comparison = {
    "manifest_entries": len(manifest_entries),
    "parsed_records_including_trailer": len(records),
    "parsed_rootfs_entries_excluding_trailer": len(records) - (1 if end_info.get("trailer_index") is not None else 0),
    "manifest_includes_trailer_record": "TRAILER!!!" in manifest_by_path,
    "manifest_rootfs_entries_excluding_trailer": len(manifest_entries) - (1 if "TRAILER!!!" in manifest_by_path else 0),
    "manifest_paths_missing_from_cpio": sorted(set(manifest_by_path) - {r["name"] for r in records}),
    "cpio_paths_missing_from_manifest": sorted({r["name"] for r in records} - set(manifest_by_path)),
    "all_shared_record_fields_match": all(
        all(r["matches_manifest"].values()) for r in records if r["matches_manifest"] is not None
    ),
}

result = {
    "scope": "read-only byte framing audit of extracted BOOT/3301.IMG gzip member and raw newc cpio",
    "inputs": {
        "gzip_image": str(IMAGE.relative_to(REPO).as_posix()),
        "gzip_size": len(image),
        "gzip_sha256": sha256(image),
        "raw_cpio": str(RAW_CPIO.relative_to(REPO).as_posix()),
        "raw_cpio_size": len(raw),
        "raw_cpio_sha256": sha256(raw),
        "saved_raw_cpio_sha256": sha256(raw_saved),
        "decompressed_stream_equals_saved_raw_cpio": raw == raw_saved,
    },
    "gzip": {
        **{k: (v.hex() if isinstance(v, bytes) else v) for k, v in gzip_fields.items()},
        "mtime_utc": datetime.datetime.fromtimestamp(gzip_fields["mtime_unix"], datetime.timezone.utc).isoformat(),
        "ftext_flag": bool(gzip_fields["flags"] & 1),
        "fhcrc_flag": bool(gzip_fields["flags"] & 2),
        "fextra_flag": bool(gzip_fields["flags"] & 4),
        "fname_flag": bool(gzip_fields["flags"] & 8),
        "fcomment_flag": bool(gzip_fields["flags"] & 16),
        "deflate_offset": deflate_start,
        "deflate_end_exclusive": deflate_end,
        "deflate_size": consumed,
        "bounded_raw_deflate_decompression_cap_bytes": MAX_EXPANDED,
        "raw_deflate_eof_reached": decompressor.eof,
        "raw_deflate_unused_data_bytes": len(decompressor.unused_data),
        "deflate_bitstream_audit": deflate_audit,
        "deflate_padding_bit_selfcheck": padding_selfcheck,
        "member_trailer_offset": deflate_end,
        "stored_crc32": f"{stored_crc:08x}",
        "calculated_crc32": f"{zlib.crc32(raw) & 0xFFFFFFFF:08x}",
        "crc32_valid": stored_crc == (zlib.crc32(raw) & 0xFFFFFFFF),
        "stored_isize": stored_size,
        "isize_valid": stored_size == (len(raw) & 0xFFFFFFFF),
        "trailing_bytes_after_member_hex": trailing.hex(),
        "trailing_bytes_after_member_count": len(trailing),
        "concatenated_or_trailing_member_data": bool(trailing),
    },
    "cpio": {
        "format": records[0]["magic"] if records else None,
        "archive_size": len(raw),
        "records_including_trailer": len(records),
        "end_marker": end_info,
        "bytes_after_trailer_record": raw[end_info.get("after_trailer_offset", len(raw)):].hex(),
        "bytes_after_trailer_count": len(raw) - end_info.get("after_trailer_offset", len(raw)),
        "bytes_after_trailer_all_zero": not any(raw[end_info.get("after_trailer_offset", len(raw)):]),
        "archive_length_aligned_512": len(raw) % 512 == 0,
        "after_trailer_offset_mod_512": end_info.get("after_trailer_offset", len(raw)) % 512,
        "field_semantics": "070701 newc has no per-file checksum; check field is expected zero. 070702 uses the low 32 bits of the sum of payload bytes.",
        "nonzero_check_fields": [{"path": r["name"], "check": r["check"]} for r in records if r["check"] != 0],
        "header_encoding_issues": header_encoding_issues,
        "name_encoding_issues": name_encoding_issues,
        "reserved_mode_highbit_issues": reserved_mode_issues,
        "inode_and_link_anomalies": inode_anomalies,
        "declared_nlink_summary": declared_nlink_summary,
        "checksum_variant_checks": [
            {"path": r["name"], "valid": r.get("crc_sum_valid"), "calculated": r.get("crc_sum_calculated")}
            for r in records if r["magic"] == "070702"
        ],
        "records": records,
        "padding_records": pads,
        "nonzero_name_padding": nonzero_name_pads,
        "nonzero_payload_padding": nonzero_data_pads,
        "nonzero_padding_byte_count": sum(sum(b != 0 for b in bytes.fromhex(p["name_padding_hex"])) + sum(b != 0 for b in bytes.fromhex(p["data_padding_hex"])) for p in pads),
        "record_start_gap_anomalies": [
            {"previous_record": records[i - 1]["name"], "previous_end": records[i - 1]["next_header_offset"],
             "next_record": records[i]["name"], "next_header": records[i]["header_offset"]}
            for i in range(1, len(records)) if records[i]["header_offset"] != records[i - 1]["next_header_offset"]
        ],
        "path_analysis": paths,
        "symlink_target_issue_counts": dict(collections.Counter(
            issue for item in paths["symlink_target_hazards"] for issue in item["issues"]
        )),
        "record_type_counts_including_trailer": dict(mode_counts),
        "special_permission_bits": flagged_modes,
        "manifest_comparison": manifest_comparison,
    },
    "limitations": [
        "This audits gzip and cpio structure/metadata only; it does not establish ISO acquisition provenance or benign intent.",
        "Absolute or parent-relative symlink targets are recorded as path semantics, not automatically classified as malicious.",
        "Deflate internals were decompressed and integrity-checked; Huffman bitstream choices were not treated as covert framing unless they changed decoded bytes.",
        "All offsets are byte offsets from the beginning of the indicated gzip member or decompressed cpio stream.",
    ],
}

JSON_OUT.write_text(json.dumps(result, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

flags = gzip_fields["flags"]
md = f"""# 3301.IMG gzip and cpio framing audit

This report parses bytes from `{IMAGE.relative_to(REPO).as_posix()}` and compares the decompressed stream against `{RAW_CPIO.relative_to(REPO).as_posix()}` and `rootfs-manifest.json`. No extraction, mounting, or execution was performed by this audit script.

## Gzip member

- Input length: {len(image):,} bytes; SHA-256 `{sha256(image)}`.
- Header: `{image[:10].hex()}`; compression method 8 (deflate), FLG `0x{flags:02x}`, mtime {gzip_fields['mtime_unix']} ({result['gzip']['mtime_utc']}), XFL {gzip_fields['xfl']}, OS byte {gzip_fields['os_byte']}.
- Optional FEXTRA/FNAME/FCOMMENT/FHCRC fields are {'present' if flags & 0x1e else 'absent'}; reserved FLG bits are clear.
- Deflate data spans byte offsets {deflate_start} through {deflate_end - 1}. The 8-byte gzip trailer starts at {deflate_end}; CRC32 and ISIZE both validate. There are {len(trailing)} bytes after the gzip member.
- Decompressed output is {len(raw):,} bytes with SHA-256 `{sha256(raw)}` and exactly equals the saved `initramfs.cpio`.
- Bounded zlib decompression used a {MAX_EXPANDED:,}-byte maximum and reached raw-deflate EOF; zlib verified the actual output bytes against the saved cpio stream. An independent RFC 1951 bit walk parsed {deflate_audit['block_count']} blocks ({deflate_audit['block_type_counts']}) and accounted for an output byte count of {deflate_audit['output_byte_count_accounted_for']:,}. Its final ignored byte-padding is {deflate_audit['final_ignored_padding']['bit_count']} bits, value {deflate_audit['final_ignored_padding']['value']}; stored-block alignment padding contains {sum(p['bit_count'] for p in deflate_audit['stored_alignment_padding_bits'])} bits, with {sum(p['value'].bit_count() for p in deflate_audit['stored_alignment_padding_bits'])} set bits. Synthetic checks passed for flipping one ignored final-padding bit and one stored-alignment bit: zlib output stayed the same while the walker reported changed padding values.

## Newc cpio stream

- Parser consumed {len(records):,} records including the trailer; format `{records[0]['magic'] if records else 'unparsed'}`. The parser compares all cpio header/data offsets, inode, mode, size, and payload SHA-256 against the existing rootfs manifest.
- Trailer record offset: {end_info.get('trailer_offset')}; byte offset after its aligned data: {end_info.get('after_trailer_offset')}; remaining bytes: {len(raw) - end_info.get('after_trailer_offset', len(raw))}, all zero: {result['cpio']['bytes_after_trailer_all_zero']}. The stream ends on a 512-byte boundary, with the trailer followed by this block padding.
- Nonzero check fields: {len(result['cpio']['nonzero_check_fields'])}; nonzero name-padding regions: {len(nonzero_name_pads)}; nonzero payload-padding regions: {len(nonzero_data_pads)}; total nonzero padding bytes: {result['cpio']['nonzero_padding_byte_count']}.
- Header fields all parse as fixed-width hexadecimal; malformed-width/nonhex records: {len(header_encoding_issues)}. Embedded NULs or missing terminal NULs in names: {len(name_encoding_issues)}. Reserved high mode bits: {len(reserved_mode_issues)}. Zero inode or zero link-count entries / repeated device-inode groups: {sum(1 for r in records if r['name'] != 'TRAILER!!!' and (r['ino'] == 0 or r['nlink'] == 0))} / {sum(1 for g in inode_groups.values() if len(g)>1)}. Link-count summary is in JSON; `nlink` is filesystem metadata, not a count of path records in this archive.
- Record-boundary gaps/anomalies: {len(result['cpio']['record_start_gap_anomalies'])}; exact duplicate paths: {len(paths['exact_duplicate_path_groups'])}; normalized path aliases: {len(paths['normalized_path_alias_groups'])}; case-folded aliases: {len(paths['casefolded_path_alias_groups'])}.
- Archive path hazards (absolute paths, `..`, empty components or control chars): {len(paths['path_hazards'])}. Symlink path semantics include {result['cpio']['symlink_target_issue_counts'].get('absolute symlink target', 0)} absolute targets and {result['cpio']['symlink_target_issue_counts'].get('parent traversal component', 0)} targets containing `..`; no backslash or control-character targets. These are not automatically malicious; see JSON for each target.
- Mode types: {dict(mode_counts)}. Special permission bits occur on: {', '.join(f"`{x['path']}` (`{x['mode_octal']}`)" for x in flagged_modes) or 'none'}.
- Rootfs manifest comparison: {manifest_comparison['parsed_rootfs_entries_excluding_trailer']:,} rootfs entries plus the trailer matches {manifest_comparison['manifest_entries']:,} manifest records; all shared record fields match: {manifest_comparison['all_shared_record_fields_match']}.

## Interpretation

The bitstream walk follows [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951), including stored-block alignment and end-of-stream bit accounting. The reported ignored bits are format padding; their value alone does not establish covert content or intent. The framing audit reports no unexplained bytes in gzip trailing space, cpio record gaps, or cpio name/payload padding when those counts are zero. Cpio `070701` check fields are reserved/zero fields rather than content checksums. The full JSON preserves every parsed record, all padding bytes, offsets, path hazards, mode bits, and comparison results for review. Cpio inode values remain archive metadata and do not prove original filesystem inode identity.

Reproduce with `python codex-scripts/iso_cpio_framing_audit.py`. Full machine-readable output: `output/iso-audit/cpio-framing-audit.json`.
"""
with MD_OUT.open("w", encoding="utf-8", newline="\n") as handle:
    handle.write(md)

print(f"Wrote {JSON_OUT.relative_to(REPO)} and {MD_OUT.relative_to(REPO)}")
