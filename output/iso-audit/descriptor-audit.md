# ISO descriptor and path-table audit

Read-only byte inspection of [archives/3301.iso](https://github.com/cicada-solvers/iddqd/blob/0e3789ad2949c62ea7fb9e3e00ded93df3b3ce07/2013/02/3301.iso); no mounting or execution. Reproduce with [codex-scripts/iso_descriptor_audit.py](../../codex-scripts/iso_descriptor_audit.py).

Input: 136,398,848 bytes (66,601 2048-byte sectors, 0 trailing bytes), SHA-256 `784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f`.

## Descriptor sequence and PVD fields

Sequential descriptor set at LBAs 16–18: Primary Volume Descriptor (type 1), El Torito Boot Record (type 0), and Volume Descriptor Set Terminator (type 255), all `CD001` version 1. No supplementary/enhanced descriptor occurs in this sequence. PVD identifiers: system `LINUX` (27 trailing spaces), volume `CDROM` (27 trailing spaces).
LE/BE copies agree: volume space [66601, 66601]; volume set [1, 1]; volume sequence [1, 1]; logical block size [2048, 2048]; path-table size [64, 64]. Root-directory extent [24, 24], byte length [2048, 2048], volume sequence [1, 1], flags 2; the root record's duplicated fields match.
All fixed PVD text fields (system/volume identifiers and volume-set, publisher, preparer, application, copyright, abstract, bibliographic identifiers) contain printable ASCII with trailing-space padding only. The six fields other than application ID are blank/all spaces. Application ID: `MKISOFS ISO 9660/HFS FILESYSTEM BUILDER & CDRECORD CD-R/DVD CREATOR (C) 1993 E.YOUNGDALE (C) 1997 J.PEARSON/J.SCHILLING` followed by 9 spaces.
PVD raw timestamps: creation, modification, and effective are `2013010323195500` with signed timezone byte 0xEC (−300 minutes); all validate as 2013-01-03 23:19:55.00 −05:00. Expiration is sixteen zero digits plus offset 0, the standard unspecified value. All four timestamp fields validate; no malformed date/time is present.
Type-L path table LBA 20; Type-M LBA 22; optional path-table LBAs 0 / 0. PVD reserved byte 7, bytes 72–79, bytes 88–119, byte 882, and bytes 1395–2047 are all zero. Application-use descriptor-relative offsets 883–1394 (absolute ISO offsets 33651–34162) contain exactly 512 spaces, 0 NULs, and no other bytes. Terminator reserved bytes 7–2047 are all zero. These fill values do not indicate hidden edits.
The Boot Record identifies `EL TORITO SPECIFICATION`, catalog LBA 29, and zero bytes in its remaining system-use area. Raw scan found 3 `CD001` instances; descriptor-identifier offsets are [32769, 34817, 36865], corresponding to LBAs [16, 17, 18]. No other sector-aligned signature was found.

## Path tables and directory tree

The declared size is 64 bytes for each table. Both tables parse as 5 entries, consume all bytes, have no parse issues, and match exactly in identifier bytes/reconstructed path, extent, parent index, and extended-attribute length. Their reconstructed paths are root, AUDIO, BOOT, DATA, and BOOT/ISOLINUX; the corresponding on-disc directory records match all five full paths, extents, and extended-attribute lengths. The directory walk visits 5 directories and 11 files with 0 errors; duplicated extent/size/volume-sequence fields agree across the PVD root record and every walked directory record (0 mismatches). Directory-record flag values are {2: 14, 0: 11} (directory bit 0x02 on directories, zero on files); no hidden, associated, multi-extent, protection, or reserved flag bits are set. All 11 file identifiers use the `;1` version suffix; directory identifiers are AUDIO, BOOT, DATA, and ISOLINUX.

## Assessment

The checked metadata is internally consistent. No descriptor/path-table alteration signal appeared in these regions. This is format consistency evidence, not proof of provenance or a comprehensive search of file payloads. Zero optional-table locations and blank reserved/application-use fields are ordinary compatible values.

Format reference: [ECMA-119, 3rd edition (2017)](https://ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf), an ISO-9660-compatible volume/file-structure standard.
