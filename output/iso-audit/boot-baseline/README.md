# Linux v3.0 boot baseline sources

These two text files were retrieved over HTTPS from the upstream Torvalds Linux v3.0 source tree for read-only format corroboration. They were inspected as text and never executed. URLs, SHA-256 digests, and relevant sections are listed in [source-manifest.json](source-manifest.json).

- [boot.txt](boot.txt): x86 boot protocol fields, payload offsets, and image checksum prose.
- [build.c](build.c): historical image builder's setup sizing, CRC accumulation, zero padding, and appended checksum implementation.

The bytes are source reference material, not files extracted from the 3301 ISO.
