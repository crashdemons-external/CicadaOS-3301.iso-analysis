# 2013 3301 ISO: static audit and documentation corrections

Status: completed static examination of the supplied image, its filesystem and
initramfs, custom boot material, known XOR uses, image containers and audio
structure. **No newly validated hidden message or executable payload was found.**
Several documentary errors were reproduced and corrected, and additional
metadata and measurable artifact properties were retained. This is not a proof
that every possible steganographic or cryptographic channel is absent.

The subsequent [low-level format audit](iso-format-audit.md) checks raw
descriptor/path-table agreement, every directory-record tail, allocation
overlaps, CPIO padding and ignored DEFLATE bits. It also compares ISOLINUX
against the official Syslinux 3.82 binary: only standard mastering-table bytes
differ. No unexplained format alteration was identified.

The actual supplied path is [archives/3301.iso](https://github.com/cicada-solvers/iddqd/blob/0e3789ad2949c62ea7fb9e3e00ded93df3b3ce07/2013/02/3301.iso). The ISO was never booted,
mounted, or used as a source of executable code. Extracted scripts and binaries
were inspected as data. Archive repositories were not modified. No packages
were installed. Analysis used repository-owned Python scripts, installed 7-Zip
for independent listings, bundled NumPy/Pillow/cryptography, and Audacity's
installed mpg123 decoder. Symlinks and device nodes were recorded rather than
created on the host.

## Image identity and filesystem accounting

The image contains 136,398,848 bytes (66,601 sectors of 2,048 bytes; approximately
130.08 MiB). Its hashes are:

```text
MD5     74062dee4093c6ca0340cda23f0e994b
SHA1    df433cba87644b35cbc47f702a02e2b58d90af6a
SHA256  784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f
```

The supplied image is byte-identical to the complete copies at
[archives/archive1/2013/02/3301.iso](https://github.com/cicada-solvers/iddqd/blob/0e3789ad2949c62ea7fb9e3e00ded93df3b3ce07/2013/02/3301.iso) and [archives/archive3/assets/2013/3301](https://github.com/cicada-solvers/documenting-cicada3301-scream314/blob/53e4282d89229b98212ef4f2349310fab6c43532/assets/2013/3301).
[archives/archive2/assets/2013/3301](https://github.com/cicada-solvers/The-Complete-Cicada3301-Archive/blob/c3127e0e9eb5afbb582d37988d6369fe38429238/assets/2013/3301) is a 137-byte Git LFS pointer, not a third
complete image: its recorded SHA-256 and size match. This establishes local
archive consistency, rather than independent original-download authentication.
The exact size also matches the contemporary IRC measurement cited in the
[documentation audit](../../output/iso-audit/documentation-claims.md).

The ISO9660 `CDROM` volume has 11 regular files under AUDIO, BOOT and DATA. Its
declared size equals the physical file size. There is no Joliet volume or Rock
Ridge POSIX metadata, no nonzero system area, and no hidden-flag file entry.
The El Torito catalog checksum validates and points to the 14,336-byte
ISOLINUX 3.82 loader, using no-emulation boot.

Every byte outside the recorded directory, path-table and file extents was
checked. All such padding/slack and the final 307,416 bytes are zero, except the
standard mkisofs identification/build sector at byte 38,912. Its recovered
[build record](../../output/iso-audit/mkisofs-build-record.txt) contains:

```text
MKI Thu Jan  3 23:19:55 2013
3.00 -o output.iso -b boot/isolinux/isolinux.bin -c boot/isolinux/boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table NewCDR/
```

The volume timestamp is `2013-01-03T23:19:55-05:00`, or
`2013-01-04T04:19:55Z`. The timezone and staging-directory name are recorded
builder metadata; they do not establish geography, identity or authorship.
The [extent table](../../output/iso-audit/iso-extent-metadata.md) preserves raw
identifiers, LBAs, byte offsets, record offsets, flags, attributes and timestamps.

`BOOT/3301.IMG` is one complete gzip stream containing an 8,324,608-byte newc
CPIO archive: 1,201 filesystem records plus `TRAILER!!!`. Its gzip CRC/size
checks pass; there are no trailing gzip bytes or nonzero bytes after the CPIO
trailer. There are 612 regular files, 291 symlinks, 173 directories and 125
special records. The [full manifest](../../output/iso-audit/rootfs-manifest.json)
retains all records, including entries not recreated as host files.

The kernel identifies itself as Linux `3.0.21-tinycore #3021`, built February 18,
2012; the rootfs release file says Tiny Core **4.7.2**. Its gzip payload was
carved to a 4,941,256-byte ELF, with no bytes beyond its ELF section table/data.
The 16,845 bytes after that gzip member belong to the surrounding bzImage
wrapper and were preserved separately. Their existence is not evidence of an
extra hidden payload; a matching upstream binary baseline would be needed to
prove the wrapper and system binaries are unchanged.

## What the documentation gets right and wrong

| Claim or source problem | Result from the image and reproduced operations |
|---|---|
| Ordinary prime delay is 0.5 seconds | **Incorrect:** 462 `sleep .05` commands, plus two `sleep 2` commands. Requested prime-stage delay totals 27.1 seconds, before overhead. |
| All primes through 3301; special pauses at 1033 and 3301 | Correct: all 464 primes occur in order, with no missing or composite entries. The shell script prints constants; it does not calculate primes. |
| Initial user is `tc` | Misleading: first-run `/sbin/autologin` executes `login -f root`; root's shell is the custom `cicada` script. `tc` does exist with an empty password field and passwordless sudo. |
| Boot show/message/reboot | Static code confirms screen clear, prime script, unsigned message, 10-second sleep and reboot request. The claimed Ctrl+C escape behavior was not tested in a running system. |
| No networking of consequence | The default Tiny Core initialization attempts DHCP; the ISO command line has no `nodhcp`. No puzzle-specific outbound network command was identified in the custom boot scripts. |
| `560.13` is an OpenPGP secret key | A false magic-byte identification: its accidental tag-5 header declares 2,394,795,858 body bytes, exceeding the file, and begins with an invalid key-version value. |
| Song is exactly 167 seconds | Rounded: the LAME delay/padding fields and decoded 7,365,632 samples at 44.1 kHz both give **167.0211338 seconds**. 167 and 761 are prime, but the integer-duration claim is not exact. |
| `1259*1031*1226 = 1,595,277,641` | Incorrect in archive3 and one wiki observations page. The correct product is **1259 × 1031 × 1229**. Archive3 also prints 363 where the documented word-value breakdown uses 376. |
| Dallas dataset-17 offset 16,433 | Does not produce the listed onion. **33,461** does. |
| Annapolis ciphertext in the later README | Damaged transcription. The corrected wiki ciphertext at offset **77,977** produces the documented onion exactly. |
| `folly` and `wisdom` identical / never used | Identity is verified. Purpose or later use remains **unverified**; unsupported community recollections do not establish a successful later solve. |

The wiki's historical ISO/boot account is at
[What Happened Part 1 (2013)](https://uncovering-cicada.fandom.com/wiki/What_Happened_Part_1_%282013%29).
The detailed later archive analysis is
[neuroretransmit's ISO README](https://github.com/neuroretransmit/cicada/blob/main/2013/002-3301/README.md).
The [local source audit](../../output/iso-audit/documentation-claims.md) records
narrow paths, line references, excerpts and provenance caveats. Source material
was preserved rather than edited to silently remove mistakes.

## Custom-file inode and metadata record

These are **CPIO archive inode fields**, not host extraction inode numbers.
Neither newc CPIO nor these ISO records supplies atime, ctime or birth time.
Packing/remastering can change inode values; numeric proximity alone does not
prove chronology or carry a puzzle meaning.

| Rootfs path | CPIO inode | Size | Mode | UID:GID | Mtime UTC |
|---|---:|---:|---|---|---|
| `/usr/local/bin/cicada` | 134034 | 106 | 100755 | 0:0 | 2013-01-02 12:02:16 |
| `/usr/local/bin/prime_echo` | 134036 | 12248 | 100755 | 0:0 | 2012-12-30 00:31:01 |
| `/usr/local/bin/message.txt` | 134039 | 65 | 100644 | 0:0 | 2013-01-03 00:08:57 |
| `/usr/local/bin/message.txt.asc` | 134079 | 948 | 100644 | 0:0 | 2013-01-03 00:08:46 |
| `/tmp/wisdom` | 142199 | 3368 | 100644 | 0:0 | 2013-01-03 01:23:42 |
| `/tmp/folly` | 175906 | 3368 | 100644 | 0:0 | 2013-01-03 01:25:10 |
| `/etc/passwd` — likely modified system file | 140005 | 175 | 100664 | 0:50 | 2012-12-27 09:19:16 |
| `/etc/init.d/tc-config` — candidate system modification | 140030 | 16062 | 100775 | 0:50 | 2012-12-27 09:17:49 |

All eight have one link and recorded device pair `8:1`. The six puzzle files
are owned by root:root; group 50 maps to staff in this rootfs. No inode is shared
by multiple filesystem records. In particular, `wisdom` and `folly` are separate
records, not hard links; their contents are identical and their mtimes differ by
88 seconds. The common mtime occurs on 604 regular files at
`2012-12-27T08:37:53Z`; timestamps alone cannot establish stock versus modified
content. The login script has this baseline date despite its relevant root
autologin behavior.

The [focused metadata report](../../output/iso-audit/custom-file-metadata.md),
[CSV](../../output/iso-audit/custom-file-metadata.csv) and
[JSON](../../output/iso-audit/custom-file-metadata.json) also record hashes,
header/data offsets, raw CPIO headers, name lengths, ownership names, link and
device fields, nearby inode records, directories and empty temporary files.

## Extracted and reproduced artifacts

The [boot signature](../../output/iso-audit/signature-verification.md) verifies
mathematically under public-key fingerprint
`6D854CD7933322A601C3286D181F01E57A35090F`, also checked using bundled
cryptography/OpenSSL. Its signer-supplied date is January 3, 2013 at 00:08:11 UTC.
The signed body and displayed unsigned message have the same visible text;
the unsigned file has one additional leading blank line. Archived text copies
match after LF/CRLF normalization. **This signs the message, not the ISO.**

All 988 archived tweet offset/hex rows reconstruct the saved 64,167-byte
stream exactly. Its XOR with the ISO MP3 reproduces the
[Gematria JPEG](../../output/iso-audit/gematria-reproduced.jpg). XORing tweet,
audio and dataset 13 also reproduces the Base64 PNG and repeating `33010`
section. The logical pattern has 42,818 bytes with no deviation, and ends at
the Twitter boundary, byte 64,167. The next byte breaks every motif phase; the
remaining overlap through the audio end does not continue that pattern.

The first-onion hint XOR `_560.00` reproduces the archived signed text, and
all seven documented phone messages can be reproduced from datasets 13/17
after the cited transcription corrections. These are confirmations of old
results, not new onion discoveries. No numbers were called or onion services
visited. [Data checks](../../output/iso-audit/data-static.md),
[stream follow-up](../../output/iso-audit/data-structure-followup.md) and
[phone-transcription audit](../../output/iso-audit/phone-xor-audit.md) retain the
exact bytes, offsets and comparisons.

Additional properties and negative checks:

- The 640×300 splash decodes completely and matches archived PNG/PPM pixels
  exactly. No extra complete RLE bytes remain. The decoded
  [splash](../../output/iso-audit/splash-decoded.png) is preserved.
- The reconstructed 521×523 PNG declares 8-bit gray+alpha, but grayscale
  values use only **0–7** and alpha is completely opaque. This restricted
  range was not explicitly described in the checked README/wiki. A
  [contrast preview](../../output/iso-audit/cicada-png-contrast-preview-audit.png) and
  bit planes [0](../../output/iso-audit/cicada-png-bitplane-0-audit.png),
  [1](../../output/iso-audit/cicada-png-bitplane-1-audit.png) and
  [2](../../output/iso-audit/cicada-png-bitplane-2-audit.png)
  show ordinary cicada imagery. Its chunks and zlib closure validate; no
  trailing bytes or extra compressed data were found. Metadata includes
  `tIME=2012-12-31 23:37:39` and 2,835 pixels/metre in each direction.
- The reproduced JPEG matches an archived original byte for byte. Its
  container has no EXIF/comment or bytes after EOI. This does **not** negate
  its already documented OutGuess message: that payload was reviewed from
  the archive, not independently re-extracted in this audit.
- The MP3 contains the documented title, artist and literal backslash-n
  poem in a 206-byte ID3v2.3 tag, followed by 6,397 complete MPEG frames
  (one Info frame and 6,396 audio frames). All use 192 kbps, 44.1 kHz joint
  stereo; no unparsed trailing bytes exist. Private/copyright/emphasis bits
  are constant, and CBR padding repeats with the expected 49-frame period.
  LAME music CRC16 `210c` and tag CRC16 `33af` both validate; Info-frame filler
  is zero. [Audio JSON](../../output/iso-audit/audio-audit.json) records these
  checks, based on the [LAME tag implementation](https://github.com/lameproject/lame/blob/master/libmp3lame/VbrTag.c).
- Left/right/mid/side spectrograms were saved and visually screened. The
  reported high-frequency line is present at approximately 15,646 Hz after
  the opening second, rather than a wide moving band. No obvious spectrogram
  text emerged. Its origin, musical key/tempo and reversed-speech claims
  were not established.
- `folly`/`wisdom` contain all 256 byte values, with entropy 7.9377 bits/byte.
  Full forward/reversed copies and tested 64/256/1024-byte prefixes do not
  occur in DATA or AUDIO. Identical contents do not identify encryption,
  plaintext or a decoy. Both data-file lengths 118,818,811 and 1,183,811 are
  prime; numerical properties alone do not establish a clue.
- Bounded searches in DATA found no valid embedded PNG, gzip, bzip2 or
  tested common-header zlib stream. Short magic-byte candidates failed
  validation. This is not an exhaustive search for every possible encoding.

## Reproducibility and remaining limits

[Output navigation](../../output/iso-audit/README.md) links the manifests,
extracted assets, previews, machine evidence and analysis scripts. The archive
and wiki record are broadly consistent with this image once the documented
timing, login, arithmetic, offset and ciphertext errors are corrected.

[Final verification](../../output/iso-audit/verification.json) passes: all 612
extracted regular-file hashes match the manifest, report links resolve, and
independent 7-Zip tests accept both ISO and CPIO. 7-Zip lists a twelfth virtual
file, `[BOOT]/Boot-NoEmul.img`, representing the 2,048-byte El Torito load region
already contained in ISOLINUX.BIN; it is not an additional ISO directory entry.

The unresolved research items are the purpose of `folly`/`wisdom`, any
unestablished audio/pixel/cryptographic channel, and a full byte comparison
against the historical Tiny Core 4.7.2 distribution. Official 4.x downloads
were removed, and no authenticated 4.7.2 baseline bytes/checksum were obtained;
the [baseline source notes](../../output/iso-audit/baseline-research.md) explain
that limit. The shared archive image
hash and valid boot-message signature do not independently authenticate every
binary in the ISO. No runtime test or exhaustive cryptanalysis was performed.
