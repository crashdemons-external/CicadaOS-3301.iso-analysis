# CicadaOS: 3301 ISO analysis

Research and evidence for `3301.iso`, the bootable CD image from Cicada 3301's
2013 puzzle. This repository examines its Tiny Core Linux environment, puzzle
files, audio and images, known XOR results, and the underlying ISO and initramfs
structures. It also checks historical archive and wiki accounts against the
image's contents.

Start with the [main analysis](findings/2013/iso-static-audit.md) and the
[low-level format audit](findings/2013/iso-format-audit.md). The
[evidence index](output/iso-audit/README.md) links to individual checks, extracted
files, reconstructed images, spectrograms, and machine-readable results.

## Findings at a glance

- **No newly validated hidden message or executable payload was found.** Known
  tweet/audio XOR images and seven documented phone-message results were
  reproduced, with transcription corrections where necessary.
- **Several historical claims need correction.** The ordinary prime-display
  delay is 0.05 seconds, initial autologin selects root, and the MP3's exact
  duration is about 167.021 seconds. The reports also document incorrect
  arithmetic, offsets, and ciphertext transcriptions.
- **Custom-file metadata is preserved.** Inode fields, permissions, owners,
  timestamps, hashes, and archive offsets are recorded for the boot scripts,
  messages, `wisdom`, and `folly`. The latter two have identical contents but
  separate CPIO records. Their purpose remains unresolved.
- **The checked filesystem structures show no unexplained alterations.**
  Directory records, path tables, allocation boundaries, archive framing, and
  ignored compression bits were examined. ISOLINUX matches the official
  Syslinux 3.82 binary outside its standard disc-mastering patch region.

These conclusions cover the checks documented here; they do not rule out every
possible steganographic channel or authenticate every system binary. The boot
message's signature verifies, but it does not sign the entire ISO.

## Repository contents

| Location | Contents |
|---|---|
| [findings/2013/](findings/2013) | Main conclusions, documentation corrections, inode metadata summary, and format audit |
| [output/iso-audit/](output/iso-audit/README.md) | Detailed evidence, 11 extracted ISO files, 612 extracted rootfs regular files, full filesystem manifests, and derived artifacts |
| [codex-scripts/](codex-scripts) | Analysis, extraction, and verification scripts |
| [reference-docs/iso-format-baselines/](reference-docs/iso-format-baselines/README.md) | Upstream boot-format and bootloader references |
| [SOURCES.md](SOURCES.md) | Archive, wiki, and IRC sources, with provenance caveats |
| [archives/3301.iso.md](archives/3301.iso.md) | Input ISO filename and hashes; the ISO itself is excluded |

The [custom-file metadata report](output/iso-audit/custom-file-metadata.md) and
[full rootfs manifest](output/iso-audit/rootfs-manifest.json) retain metadata for
records that cannot be represented by ordinary extracted files, including
symlinks and device nodes. Inode values belong to the CPIO archive; timestamps
are not proof of creation time or authorship.

## Working with the evidence

The extracted executables and scripts are untrusted research material. The
reports describe static inspection; the ISO was not mounted, booted, or executed.

Two large artifacts, `560.13` and `audio-spectral-data.npz`, use Git LFS. After
cloning, retrieve them with:

```sh
git lfs pull
```

Checks requiring the original image expect a matching file at
`archives/3301.iso`; some historical reproductions also require the external
source archives listed in [SOURCES.md](SOURCES.md). The
[file manifest](export-manifest.json) and
[integrity report](export-verification.json) record hashes and local-link checks
for the repository's evidence files.
