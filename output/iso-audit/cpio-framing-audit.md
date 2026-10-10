# 3301.IMG gzip and cpio framing audit

This report parses bytes from [output/iso-audit/iso-files/BOOT/3301.IMG](iso-files/BOOT/3301.IMG) and compares the decompressed stream against [output/iso-audit/initramfs.cpio](initramfs.cpio) and [rootfs-manifest.json](rootfs-manifest.json). No extraction, mounting, or execution was performed by this audit script.

## Gzip member

- Input length: 5,494,774 bytes; SHA-256 `3fcbb8abaf9d876985e8122e94f60b306a06401ec95b743d52da2e2324a37f42`.
- Header: `1f8b08001958e6500003`; compression method 8 (deflate), FLG `0x00`, mtime 1357273113 (2013-01-04T04:18:33+00:00), XFL 0, OS byte 3.
- Optional FEXTRA/FNAME/FCOMMENT/FHCRC fields are absent; reserved FLG bits are clear.
- Deflate data spans byte offsets 10 through 5494765. The 8-byte gzip trailer starts at 5494766; CRC32 and ISIZE both validate. There are 0 bytes after the gzip member.
- Decompressed output is 8,324,608 bytes with SHA-256 `2877209198fc8ef40f581a1e1e4ca575f59beb44b5cd7097093c4f44aa161b31` and exactly equals the saved [initramfs.cpio](initramfs.cpio).
- Bounded zlib decompression used a 134,217,728-byte maximum and reached raw-deflate EOF; zlib verified the actual output bytes against the saved cpio stream. An independent RFC 1951 bit walk parsed 219 blocks ({'dynamic': 213, 'stored': 6}) and accounted for an output byte count of 8,324,608. Its final ignored byte-padding is 6 bits, value 0; stored-block alignment padding contains 21 bits, with 0 set bits. Synthetic checks passed for flipping one ignored final-padding bit and one stored-alignment bit: zlib output stayed the same while the walker reported changed padding values.

## Newc cpio stream

- Parser consumed 1,202 records including the trailer; format `070701`. The parser compares all cpio header/data offsets, inode, mode, size, and payload SHA-256 against the existing rootfs manifest.
- Trailer record offset: 8324344; byte offset after its aligned data: 8324468; remaining bytes: 140, all zero: True. The stream ends on a 512-byte boundary, with the trailer followed by this block padding.
- Nonzero check fields: 0; nonzero name-padding regions: 0; nonzero payload-padding regions: 0; total nonzero padding bytes: 0.
- Header fields all parse as fixed-width hexadecimal; malformed-width/nonhex records: 0. Embedded NULs or missing terminal NULs in names: 0. Reserved high mode bits: 0. Zero inode or zero link-count entries / repeated device-inode groups: 0 / 0. Link-count summary is in JSON; `nlink` is filesystem metadata, not a count of path records in this archive.
- Record-boundary gaps/anomalies: 0; exact duplicate paths: 0; normalized path aliases: 0; case-folded aliases: 0.
- Archive path hazards (absolute paths, `..`, empty components or control chars): 0. Symlink path semantics include 12 absolute targets and 173 targets containing `..`; no backslash or control-character targets. These are not automatically malicious; see JSON for each target.
- Mode types: {'directory': 173, 'symlink': 291, 'regular': 612, 'block_device': 65, 'character_device': 60, 'unknown': 1}. Special permission bits occur on: `opt` (`042775`), `var/spool/lpd` (`042775`), `tmp` (`041777`).
- Rootfs manifest comparison: 1,201 rootfs entries plus the trailer matches 1,202 manifest records; all shared record fields match: True.

## Interpretation

The bitstream walk follows [RFC 1951](https://www.rfc-editor.org/rfc/rfc1951), including stored-block alignment and end-of-stream bit accounting. The reported ignored bits are format padding; their value alone does not establish covert content or intent. The framing audit reports no unexplained bytes in gzip trailing space, cpio record gaps, or cpio name/payload padding when those counts are zero. Cpio `070701` check fields are reserved/zero fields rather than content checksums. The full JSON preserves every parsed record, all padding bytes, offsets, path hazards, mode bits, and comparison results for review. Cpio inode values remain archive metadata and do not prove original filesystem inode identity.

Reproduce with `python codex-scripts/iso_cpio_framing_audit.py`. Full machine-readable output: [output/iso-audit/cpio-framing-audit.json](cpio-framing-audit.json).
