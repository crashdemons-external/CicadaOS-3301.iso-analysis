# Static audit of the extracted 3301.iso root filesystem

Scope: read-only inspection of [output/iso-audit/rootfs](rootfs) and [rootfs-manifest.json](rootfs-manifest.json). No extracted code or binary was executed, and symlinks were not followed. No package was used.

## Main findings

- The manifest contains 1,202 entries. 604 regular files have the common archive mtime 2012-12-27T08:37:53+00:00 (Unix 1356597473). Eight regular files differ: `etc/init.d/tc-config` (2012-12-27T09:17:49+00:00), `etc/passwd` (2012-12-27T09:19:16+00:00), `usr/local/bin/prime_echo` (2012-12-30T00:31:01+00:00), `usr/local/bin/cicada` (2013-01-02T12:02:16+00:00), `usr/local/bin/message.txt.asc` (2013-01-03T00:08:46+00:00), `usr/local/bin/message.txt` (2013-01-03T00:08:57+00:00), `tmp/wisdom` (2013-01-03T01:23:42+00:00), and `tmp/folly` (2013-01-03T01:25:10+00:00). The two December 27 edits precede the puzzle-specific files and should not be grouped with them. Archive mtimes alone do not prove authoring time.
- `etc/inittab` starts `rcS` and configures tty1 getty with `/sbin/autologin`. Its first invocation runs `login -f root`; root's shell is `/usr/local/bin/cicada`. The `tc` account exists with an empty password field and `NOPASSWD: ALL` in `sudoers`, but is not the initial autologin target. `cicada` clears the screen, invokes `prime_echo`, prints `message.txt`, waits 10 seconds, and requests reboot.
- `prime_echo` contains 464 literal entries and exactly matches every prime from 2 through 3301. It requests 0.05-second sleeps after 462 entries and two-second sleeps at 1033 and 3301, for 27.1 seconds of requested delay before shell and terminal overhead. This differs from the 0.5-second ordinary-delay claim in one documentation source; the script says `.05`.
- `opt/bootsync.sh` sets hostname `box` and backgrounds `opt/bootlocal.sh`, which contains only comments. No regular-file hardlink groups were found. The ISO command line has `loglevel=3` without `nodhcp`, and `tc-config` starts `/etc/init.d/dhcp.sh` in the background unless `NODHCP` is set. Thus default Tiny Core boot attempts DHCP configuration. No puzzle-specific outbound networking command was found. Generic Tiny Core TFTP and cron service scripts are present; presence alone does not establish they are enabled.
- `tmp/folly` and `tmp/wisdom` are each 3,368 bytes and have identical SHA-256 (`7e5ec097728197f5c0dba0729980565658fba486965809ffa25e3910a31c385a`), so they are byte-identical despite different names and mtimes. `message.txt` contains `@1231507051321`, “The key is all around you,” and ends in `3301`. Its adjacent cleartext signature verifies against the local Cicada public key; see [signature-verification.md](signature-verification.md) for the fingerprint, signer-supplied timestamp, and method.

## Inventory and limitations

There are 1,202 manifest entries and no regular-file inode groups with multiple paths. `etc/skel/.ash_history` is empty. The manifest records `home/tc` but no files below it; the extracted host tree omits that empty directory.

Stock Tiny Core initialization contains generic mount, module, DHCP, and service-management code. This report distinguishes those default OS behaviors from puzzle-specific startup behavior. Static analysis cannot establish all runtime behavior in a VM or authenticate the original ISO source.

Machine-readable details and hashes: [output/iso-audit/rootfs-static.json](rootfs-static.json). Reproduce with `python codex-scripts/iso_rootfs_static.py`.
