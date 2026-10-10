# 3301 ISO audit outputs

The durable result is [the 2013 ISO audit](../../findings/2013/iso-static-audit.md).
Its extension is [the low-level format audit](../../findings/2013/iso-format-audit.md).
All binary inputs and extracted code remain untrusted data. Nothing from the
ISO was booted, mounted, imported as Python, installed or executed. Extracted
regular files include their original script/binary content for inspection;
symlinks and device nodes exist only as manifest records.

| Evidence | Contents |
|---|---|
| [iso-layout.json](iso-layout.json) | Whole-image hashes, descriptors, every allocated extent and slack/padding scan |
| [iso-inventory.json](iso-inventory.json) | Raw ISO directory records, attributes and per-file hashes |
| [iso-extent-metadata.md](iso-extent-metadata.md), [TSV](iso-extent-metadata.tsv), [JSON](iso-extent-metadata.json) | ISO file identifiers, physical offsets and timestamp conversions |
| [rootfs-manifest.json](rootfs-manifest.json) | All 1,201 filesystem records plus the CPIO trailer, inode/mode/owner/link/device/offset fields and raw headers |
| [custom-file-metadata.md](custom-file-metadata.md), [CSV](custom-file-metadata.csv), [JSON](custom-file-metadata.json) | Focused custom-file metadata and nearby inode records |
| [rootfs-static.md](rootfs-static.md) | Prime verification, startup flow, accounts, DHCP, file timestamps |
| [signature-verification.md](signature-verification.md), [independent RSA check](signature-independent.json) | Boot-message RSA verification and exact/normalized archived-copy comparisons |
| [documentation-claims.md](documentation-claims.md) | Archive/wiki/IRC claims, source references, arithmetic and timing errors |
| [data-static.md](data-static.md), [data-followup.md](data-followup.md), [data-structure-followup.md](data-structure-followup.md) | Hash/copy checks, entropy/histograms, stream/prefix searches, tweet reconstruction and shortcut structure |
| [phone-xor-audit.md](phone-xor-audit.md) | All seven dataset-13/17 phone results and transcription-error variants |
| [image-container-audit.md](image-container-audit.md) | PNG chunks, alpha/gray values, zlib closure, JPEG segments and comparison scope |
| [audio-audit.json](audio-audit.json) | MP3 frames/tags, exact duration, CBR padding, LAME CRCs, tone tracking and decoder identity |
| [structural-followup.json](structural-followup.json) | Local ISO copies/LFS digest, builder record, El Torito fields, false PGP magic and kernel structure |
| [baseline-research.md](baseline-research.md) | Why no authenticated Tiny Core 4.7.2 byte baseline was compared |
| [descriptor-audit.md](descriptor-audit.md), [JSON](descriptor-audit.json) | Every volume-descriptor field, fill region, timestamp and both path tables |
| [directory-record-audit.md](directory-record-audit.md), [JSON](directory-record-audit.json) | All directory records including dot entries, padding, names, sector slack and allocation overlap checks |
| [cpio-framing-audit.md](cpio-framing-audit.md), [JSON](cpio-framing-audit.json) | Raw newc record framing, aliases, mode/header encodings and DEFLATE ignored bits |
| [boot-raw-audit.json](boot-raw-audit.json), [Linux kernel format check](linux-boot-baseline.md) | Catalog/pointer/checksum validation, official ISOLINUX byte comparison, standard disc end padding and kernel bounds/CRC |
| [verification.json](verification.json), [ISO test](7zip-iso-test.txt), [CPIO test](7zip-cpio-test.txt) | Final extracted-file hash checks, report links, signatures/results and independent 7-Zip archive tests |

[iso-files/](iso-files) contains the 11 ISO regular files; [rootfs/](rootfs) contains 612 CPIO
regular files, including six empty files. Empty directories, Unix symlinks and
device records are preserved in the manifest rather than recreated. The raw
decompressed archive is [initramfs.cpio](initramfs.cpio). Its bounds/footer
evidence is in [compression.json](compression.json).

Useful extracted or reproduced artifacts:

- [mkisofs build record](mkisofs-build-record.txt)
- [decoded splash](splash-decoded.png) and [decoder metadata](splash-decode-report.json)
- [reproduced Gematria JPEG](gematria-reproduced.jpg)
- [reproduced shortcut PNG](cicada-reproduced.png), [contrast preview](cicada-png-contrast-preview-audit.png), bit planes [0](cicada-png-bitplane-0-audit.png), [1](cicada-png-bitplane-1-audit.png) and [2](cicada-png-bitplane-2-audit.png)
- [raw reconstructed tweets](twitter-rebuilt.bin) and [triple-XOR text](twitter-audio-data13-xor.txt)
- [first-onion hint XOR](clue-xor.bin) and [phone result at offset 12,821](third-onion-offset-12821.bin)
- [left](audio-spectrogram-left.png), [right](audio-spectrogram-right.png), [mid](audio-spectrogram-mid.png) and [side](audio-spectrogram-side.png) spectrograms; [numeric FFT data](audio-spectral-data.npz)
- [carved kernel ELF](kernel-vmlinux.elf) and [bytes after its gzip member](kernel-after-gzip.bin), retained as data without execution

The parser/extractor and most checks use the Python standard library. Scripts
are in [codex-scripts/](../../codex-scripts): [iso_audit.py](../../codex-scripts/iso_audit.py), [iso_structural_followup.py](../../codex-scripts/iso_structural_followup.py),
[iso_extent_metadata.py](../../codex-scripts/iso_extent_metadata.py), [iso_rootfs_static.py](../../codex-scripts/iso_rootfs_static.py), [iso_custom_metadata.py](../../codex-scripts/iso_custom_metadata.py),
[iso_signature_audit.py](../../codex-scripts/iso_signature_audit.py), [iso_signature_independent.py](../../codex-scripts/iso_signature_independent.py), [iso_data_static.py](../../codex-scripts/iso_data_static.py),
[iso_data_followup.py](../../codex-scripts/iso_data_followup.py), [iso_data_structure_followup.py](../../codex-scripts/iso_data_structure_followup.py), [phone_xor_audit.py](../../codex-scripts/phone_xor_audit.py),
[iso_derived_artifacts.py](../../codex-scripts/iso_derived_artifacts.py), [iso_splash_audit.py](../../codex-scripts/iso_splash_audit.py), [image_container_audit.py](../../codex-scripts/image_container_audit.py),
[iso_audio_audit.py](../../codex-scripts/iso_audio_audit.py), and [iso_audit_verify.py](../../codex-scripts/iso_audit_verify.py). The image/audio and independent RSA scripts use the
already bundled Python environment; audio decoding uses the installed Audacity
`mpg123.dll`. No dependency installer or archive-provided solver was run.

Additional raw-format scripts are [iso_descriptor_audit.py](../../codex-scripts/iso_descriptor_audit.py),
[iso_directory_record_audit.py](../../codex-scripts/iso_directory_record_audit.py), [iso_cpio_framing_audit.py](../../codex-scripts/iso_cpio_framing_audit.py) and
[iso_boot_raw_audit.py](../../codex-scripts/iso_boot_raw_audit.py), using the standard library. The boot script optionally
downloads the official Syslinux release with `--download-baseline`; it reads
three selected regular members as data and never runs package code.

The binary artifacts reproduce historical results or preserve original bytes;
they should not be mistaken for new primary sources. Inodes are CPIO fields,
not the Windows files' identities. Modification timestamps are metadata rather
than proof of creation time or authorship.
