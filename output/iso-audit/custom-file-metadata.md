# Custom and related rootfs file metadata

Source: [output/iso-audit/rootfs-manifest.json](rootfs-manifest.json). The table records cpio manifest fields for the six puzzle-associated files, two likely system-file modifications, related paths including empty `/tmp/aberr`, related directories, and `/sbin/autologin` for boot context. The system-file classifications are inferred from their role and nonbaseline timestamps; the autologin and `/tmp/aberr` classifications are explicitly unproven.

| Path | Classification | Cpio inode | Mode | UID:GID | Nlink | Size | Mtime UTC | SHA-256 | Data offset |
|---|---|---:|---|---|---:|---:|---|---|---:|
| `tmp/folly` | puzzle artifact | 175906 | `-rw-r--r-- (100644)` | 0:0 (root:root) | 1 | 3368 | 2013-01-03T01:25:10+00:00 | `7e5ec097728197f5c0dba0729980565658fba486965809ffa25e3910a31c385a` | 8317484 |
| `tmp/wisdom` | puzzle artifact | 142199 | `-rw-r--r-- (100644)` | 0:0 (root:root) | 1 | 3368 | 2013-01-03T01:23:42+00:00 | `7e5ec097728197f5c0dba0729980565658fba486965809ffa25e3910a31c385a` | 8320976 |
| `tmp/aberr` | related empty temporary file; authorship unproven | 140047 | `-rw-rw-rw- (100666)` | 0:50 (root:staff) | 1 | 0 | 2012-12-27T08:37:53+00:00 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 8316940 |
| `usr/local/bin/cicada` | custom boot script | 134034 | `-rwxr-xr-x (100755)` | 0:0 (root:root) | 1 | 106 | 2013-01-02T12:02:16+00:00 | `e5231e14d404c43a74820c3ea9067c4900c36b03438660cfb69c9aa31fc3b75c` | 6581904 |
| `usr/local/bin/prime_echo` | custom prime display script | 134036 | `-rwxr-xr-x (100755)` | 0:0 (root:root) | 1 | 12248 | 2012-12-30T00:31:01+00:00 | `1ab3a8f4520a3d93784aea137847e0c7f77d9fff4df02d481b62d13280753350` | 6582352 |
| `usr/local/bin/message.txt` | puzzle message | 134039 | `-rw-r--r-- (100644)` | 0:0 (root:root) | 1 | 65 | 2013-01-03T00:08:57+00:00 | `c4ba455cd05d98743751d89e521c8fa4252a472734438f10067cbb899fdfe6a0` | 6582148 |
| `usr/local/bin/message.txt.asc` | signed puzzle message | 134079 | `-rw-r--r-- (100644)` | 0:0 (root:root) | 1 | 948 | 2013-01-03T00:08:46+00:00 | `4401b6536f99d9716e91b10bf99777d4a75dce58fe50533cb847238af17eaf6e` | 6594740 |
| `etc/passwd` | likely modified system account file (classification inferred) | 140005 | `-rw-rw-r-- (100664)` | 0:50 (root:staff) | 1 | 175 | 2012-12-27T09:19:16+00:00 | `5c6b7a818b18310eb7e3b151d55fabf8fe6ac109a9a2d9c420c77668a9e3c983` | 7745984 |
| `etc/init.d/tc-config` | likely modified system startup file (classification inferred) | 140030 | `-rwxrwxr-x (100775)` | 0:50 (root:staff) | 1 | 16062 | 2012-12-27T09:17:49+00:00 | `4ecb6f2c2c4764f7f8919b98209e85cbb3cc09510c8e0c67ce56d4cbc28e7ce4` | 7711832 |
| `tmp` | related directory | 180295 | `drwxrwxrwt (041777)` | 0:50 (root:staff) | 2 | 0 | 2013-01-03T01:25:10+00:00 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 8316820 |
| `usr/local/bin` | related directory | 180272 | `drwxrwxr-x (040775)` | 0:50 (root:staff) | 2 | 0 | 2013-01-03T00:08:57+00:00 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 6581772 |
| `sbin/autologin` | related stock-date login script; modification classification inferred | 139876 | `-rwxrwxr-x (100775)` | 0:50 (root:staff) | 1 | 136 | 2012-12-27T08:37:53+00:00 | `e258b3373ddcebdc17d5e5fe68d3fb348420de69be9ab7bbd0fbd877578c82e4` | 8063580 |

## Metadata observations

- The two temporary puzzle files each have size 3,368 bytes, mode `100644`, UID:GID `0:0` (root:root), one link, device pair `8:1`, and byte-identical SHA-256. `wisdom` has mtime 1357176222 (2013-01-03T01:23:42+00:00); `folly` has mtime 1357176310 (2013-01-03T01:25:10+00:00), an 88-second difference.
- The four `/usr/local/bin` puzzle files have UID:GID `0:0`, one link, and device pair `8:1`. `cicada` and `prime_echo` are executable (`100755`); message files are `100644`.
- `etc/passwd` and `etc/init.d/tc-config` have numeric ownership root:staff (`0:50`) and differ from the common rootfs mtime. This supports treating them as likely adjusted system files, but their cpio metadata alone does not prove who changed them or when.
- `/sbin/autologin` is executable and records root:staff ownership, one link, device pair `8:1`, and the common rootfs timestamp. It is included because its first-login behavior is operationally relevant; the metadata does not establish that it was custom-authored.
- The manifest has 1202 entries, 1 zero-inode path (`TRAILER!!!`, the cpio end marker), 0 duplicate-inode groups, and 0 groups of multiple regular paths sharing an inode. It records 6 zero-length regular files, including `/tmp/aberr`; the JSON lists all of them. Device pair counts are summarized there as well. These are properties of this archive manifest, not a reconstruction of original on-disk filesystem identities.

The “neighbor records” section in the JSON includes paths with cpio inode values within +/- 3 of each target inode. These values may be useful for spotting packing or numbering patterns; proximity alone does not show directory adjacency, authorship, or chronology.

Reproduce the JSON, CSV, and this UTF-8 report with `python codex-scripts/iso_custom_metadata.py`. No extracted code or binary is executed.
