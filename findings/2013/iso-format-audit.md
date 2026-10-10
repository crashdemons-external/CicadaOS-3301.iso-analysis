# 2013 CD image: low-level ISO and initramfs format audit

Status: **no unexplained alteration was identified in the checked format
structures or padding.** The bootloader has only ordinary disc-mastering
patches relative to an official upstream binary. This extends the
[content and metadata audit](iso-static-audit.md); it does not authenticate
every executable or rule out arbitrary steganography in file contents or
compression choices.

The source remains [archives/3301.iso](https://github.com/cicada-solvers/iddqd/blob/0e3789ad2949c62ea7fb9e3e00ded93df3b3ce07/2013/02/3301.iso), SHA-256
`784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f`.
Neither the ISO nor its executables were mounted, booted or executed. Three
Luna agents independently checked descriptors, directory records and initramfs
framing, followed by review and cross-checks. Downloaded upstream material was
read as data, without installing or running it.

## ISO structures a file listing can hide

| Region or mechanism | Byte-level result |
|---|---|
| System area, bytes 0–32,767 | Entirely zero; no embedded MBR/GPT/Apple partition-map boot structure there. |
| Volume descriptors | Only the PVD at sector 16, El Torito record at 17 and terminator at 18. Whole-image `CD001` search finds only these three identifiers; sector-aligned UDF recognition signatures are absent. |
| Duplicate numeric fields | Little- and big-endian copies agree for volume size, set/sequence numbers, block size, path-table size, directory extents, lengths and sequence numbers. No differing parser view was found. |
| Alternate directory namespaces | No Joliet/enhanced descriptor or Rock Ridge/SUSP system-use records. No optional path-table copies. |
| Path tables | Type L at sector 20 and Type M at 22 contain five matching entries, describing the same root and four child directories. They agree with the directory tree. |
| PVD application-use region | Descriptor offsets 883–1394, absolute ISO offsets 33,651–34,162, contain 512 ASCII spaces. Reserved PVD regions contain zeros. |
| All directory records | All 25 records, including each `.` and `..`, were examined. Self/parent pointers agree, identifier padding is zero, and every unused sector tail after a zero record-length byte is zero. |
| Less-visible file attributes | No hidden/associated/protection/record-format flags, reserved flags, multi-extent files, extended-attribute blocks, interleaving or system-use data. |
| Name and allocation tricks | No duplicate or normalized-name collisions, directory cycles, or overlapping named file/directory sectors. Raw `VMLINUZ.;1` explains the trailing-period/version differences seen in reader listings. |
| File and disc slack | File-sector slack is zero. The end consists of 216 bytes of last-file sector slack followed by exactly 150 zero sectors (307,200 bytes), matching the documented default mastering padding. |

The one nonzero region outside allocated file/directory/path-table data is the
already recovered mkisofs build record in sector 19. It is a recognizable
builder record containing a timestamp and command, rather than an unexplained
binary allocation. Default 150-sector end padding and boot-information-table
patching are described in the
[mastering-tool manual](https://manpages.debian.org/bookworm/genisoimage/genisoimage.1.en.html).

Detailed evidence: [descriptor audit](../../output/iso-audit/descriptor-audit.md),
[directory record audit](../../output/iso-audit/directory-record-audit.md) and
[original allocation accounting](../../output/iso-audit/iso-layout.json).

## Boot structures and an upstream byte comparison

The boot catalog occupies sector 29 and has one BIOS no-emulation entry loading
2,048 bytes from sector 30. Its validation checksum and key validate. Unused
validation/default-entry fields and all 1,984 bytes after the default entry are
zero, so no alternate catalog entry or catalog-padding payload was found.
The loaded bytes equal the prefix of the listed `ISOLINUX.BIN` file.

The loader's boot-information table records PVD LBA 16, loader LBA 30, length
14,336 and checksum `0x6157b0d6`. All pointers/lengths agree with the directory
and catalog, and the computed 32-bit sum over bytes 64 onward equals that
checksum. Its 40 reserved bytes are zero.

For a stronger check, the official
[Syslinux 3.82 release](https://cdn.kernel.org/pub/linux/utils/boot/syslinux/3.xx/syslinux-3.82.tar.gz)
was downloaded over HTTPS. Its 3,795,792-byte archive SHA-256,
`7dac4117d44a3ef01bbf2d385419ec056ba58b657457ea19a0f9a64c3b00a43d`,
matches the official checksum list. **The ISO loader matches the upstream
14,336-byte `core/isolinux.bin` everywhere outside bytes 8–63.** Only 41 bytes
differ:

- Byte 12 changes from `00` to `1e`, setting loader LBA 30.
- Bytes 24–63 change ten upstream `0xdeadbeef` reserved placeholders to zeros.

These differences lie entirely in the documented mastering patch region.
The upstream assembly identifies the reserved placeholders; the release's
instructions use the same boot-information-table option as the recovered
builder command. No additional loader code patch was found. The official
checksum was checked, but its detached OpenPGP authentication was not verified.
Sources and byte differences are preserved in
[boot-raw-audit.json](../../output/iso-audit/boot-raw-audit.json) and
[the baseline files](../../output/iso-audit/boot-baseline). The upstream text
sources are also preserved as
[indexed working references](../../reference-docs/iso-format-baselines/README.md).

The kernel's advertised setup/protected-code lengths account for its complete
2,491,968-byte file. Its advertised compressed payload begins at byte 13,922
and spans exactly the previously carved 2,461,201-byte gzip member. Thus the
16,845 subsequent bytes are within the advertised kernel wrapper, rather than
bytes appended beyond the header's file length. Payload framing and the
recorded checksum relationship are retained in the boot audit. This is not a
byte comparison of the kernel against Tiny Core's original distribution.
The appended word `0x81b64dc1` matches the historical builder's CRC convention;
the complete image has zero residue in that convention. The
[kernel construction check](../../output/iso-audit/linux-boot-baseline.md)
records the source comparison and checksum values. Header interpretation follows the
[Linux boot protocol](https://www.kernel.org/doc/html/latest/arch/x86/boot.html).

## Initramfs archive and ignored compression bits

`3301.IMG` is a gzip member containing a newc CPIO archive, rather than an ext
filesystem with separate inode tables, a journal or a free-space bitmap.
There is no gzip extra field, filename, comment or second member. CRC32 and
ISIZE validate; the decompressed bytes equal the saved raw CPIO exactly.

An independent RFC 1951 bit walker accounts for 219 DEFLATE blocks: 213 dynamic
Huffman blocks and six stored blocks. Its output byte count agrees with zlib's
8,324,608-byte output. **The six ignored bits at the end and all 21 stored-block
alignment bits are zero.** These checks cover small gaps a conventional
decompressor ignores; they do not determine whether legal Huffman or LZ77
encoding choices were deliberately selected.

Synthetic checks also pass: deliberately flipping a final ignored bit or a
stored-block alignment bit leaves zlib's output unchanged, while the bit
walker detects the changed padding value. This checks the overlooked-bit
detection itself rather than merely rechecking successful decompression.

Every one of the 1,202 CPIO records, including the trailer, was parsed without
skipping gaps. Name/data alignment padding is zero, headers use fixed-width
hex fields, names have no internal NUL, and reserved high mode bits/check fields
are zero. No duplicate path, normalized alias, repeated device/inode group or
unexpected archive path was found. The trailer is followed by exactly 140 zero
bytes, bringing the stream to a 512-byte boundary. Existing absolute or
parent-relative symlink targets were recorded as normal Unix path semantics.

[CPIO/gzip framing evidence](../../output/iso-audit/cpio-framing-audit.md)
preserves every header, padding region, compression-block boundary and ignored
bit value. CPIO inode/link fields remain metadata rather than evidence of
authorship or original inode identity.

## Limits

This audit found no concealed records, conflicting metadata views or payload
in the checked unused bytes/bits. A valid checksum can be recomputed after an
intentional edit. Arbitrary compression choices, timestamps, allocation order
and opaque file contents can still encode information without violating the
format. A full Tiny Core 4.7.2 binary baseline remains unavailable.

[Final verification](../../output/iso-audit/verification.json) includes an
independent 7-Zip read of every ISO file: all 11 sizes and SHA-256 values match
the raw parser's results. The archive tests and metadata/framing checks pass.

The supplied image has 2,048-byte logical sectors. It does not preserve raw CD
sector error-correction bytes, subchannels, physical track/session layout or
lead-in/lead-out data, so those physical-disc channels cannot be audited from
this file alone. Nothing in these format checks establishes what
`folly`/`wisdom` were intended to mean.
