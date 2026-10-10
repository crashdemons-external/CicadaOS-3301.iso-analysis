# Tiny Core 4.7.2 baseline availability and provenance

The extracted system identifies itself as Tiny Core 4.7.2 and has a `3.0.21-tinycore` module tree. I looked for the matching official baseline so the rootfs could be compared against upstream bytes. No authenticated baseline bytes or official 4.7.2 checksum were obtainable, so I did not perform a comparison or use a substitute release.

## What the primary sources establish

The Tiny Core administrator announced that the 4.x release and extension repositories would be removed at the end of 2024, then confirmed on 2025-01-03 that “4.x has been removed.” The official [removal announcement](https://forum.tinycorelinux.net/index.php?topic=27321.0) accounts for the old directory no longer being available.

The project’s [Core documentation](https://distro.ibiblio.org/tinycorelinux/corebook.pdf) documents the 4.x `release/distribution_files` layout and the base filenames `core.gz` and `vmlinuz`. Its current [downloads page](https://distro.ibiblio.org/tinycorelinux/downloads.html) lists historical base-release archives from 5.x onward, not 4.x.

Contemporaneous forum discussions provide supporting version context. A 2012-12-27 [4.7.2 user report](https://forum.tinycorelinux.net/index.php?topic=14575.0) refers to its `vmlinuz` and `core.gz`. A 2012-11-11 [kernel discussion](https://forum.tinycorelinux.net/index.php?topic=14394.0) reports `3.0.21-tinycore #3021`; a project maintainer replies that it is the stock Linux 3.0 kernel and points to project sources. These discussions support the expected naming and kernel context, but they do not provide authenticated hashes for this ISO or its embedded rootfs.

## Locations and checksums

The historical official paths checked were:

- `http://tinycorelinux.net/4.x/x86/archive/4.7.2/Core-4.7.2.iso`
- `http://tinycorelinux.net/4.x/x86/archive/4.7.2/`
- `http://repo.tinycorelinux.net/4.x/x86/archive/4.7.2/`
- `https://distro.ibiblio.org/tinycorelinux/4.x/x86/release/distribution_files/`

The shell could not resolve the two Tiny Core hostnames. The official distro.ibiblio.org distribution-files path returned 404 in the browser fetch. The official project sources located here did not publish an ISO SHA-256/SHA-1 or 4.7.2 `core.gz`/`vmlinuz` checksum. Current project indexes do publish adjacent MD5 files, but no 4.7.2 digest was found.

A forum participant later linked a [4.x Internet Archive zip](https://forum.tinycorelinux.net/index.php?topic=27148.0) after the project’s removal announcement. That is a community-provided mirror lead, not a project-authenticated copy or checksum. I did not download or treat it as a trusted baseline.

## Audit implication

The current rootfs hashes and metadata remain useful for documenting what is inside the extracted image. Without a trusted 4.7.2 reference, differences in files such as `/etc/passwd`, `/etc/init.d/tc-config`, or `/sbin/autologin` cannot be labeled as modifications from upstream based only on their content or timestamps. No 4.7.7 or other nearby version was substituted for the missing baseline.

Full source URLs, observations, and network status are recorded in [output/iso-audit/baseline-research.json](baseline-research.json).
