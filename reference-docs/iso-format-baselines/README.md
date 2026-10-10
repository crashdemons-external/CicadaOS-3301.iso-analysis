# ISO format and construction references

Byte-preserving upstream source/document copies retrieved on 2026-10-10 for the
[2013 low-level ISO audit](../../findings/2013/iso-format-audit.md). These are
format references, not Cicada puzzle source material. No saved code was run.

- [linux-v3.0-boot.txt](linux-v3.0-boot.txt) and [linux-v3.0-build.c](linux-v3.0-build.c): Torvalds Linux v3.0 source
  tree, describing x86 payload bounds and image CRC construction.
- [syslinux-3.82-isolinux.asm](syslinux-3.82-isolinux.asm) and [syslinux-3.82-isolinux.txt](syslinux-3.82-isolinux.txt): selected members
  of the official Syslinux 3.82 release, describing boot-information-table
  fields and the mastering process. The package hash matched the checksum
  list obtained from the same official HTTPS host; detached OpenPGP
  authentication was not independently verified.

[Source manifest](source-manifest.json) records exact URLs, lengths and SHA-256
digests. Working copies and the downloaded Syslinux package remain in
[output/iso-audit/boot-baseline/](../../output/iso-audit/boot-baseline) for reproduction. The original Tiny Core
4.7.2 distribution was not obtained.
