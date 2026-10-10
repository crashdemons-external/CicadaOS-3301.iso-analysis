# 3301 ISO analysis

Copied on 2026-10-10 from the completed static audit. Start with:

- [Content, documentation and inode report](findings/2013/iso-static-audit.md)
- [Low-level ISO/filesystem format report](findings/2013/iso-format-audit.md)
- [All output, extracted artifacts and evidence](output/iso-audit/README.md)
- [Custom-file metadata](output/iso-audit/custom-file-metadata.md)
- [Archive citations and web sources](SOURCES.md)
- [Upstream format references](reference-docs/iso-format-baselines/README.md)
- [ISO filename and hashes](archives/3301.iso.md)
- [Copy integrity and local-link verification](export-verification.json)
- [Publication copy manifest](export-manifest.json)

The folder preserves the source project's relative layout. All generated outputs,
612 extracted rootfs regular files, 11 extracted ISO files, analysis scripts,
and upstream baseline material are included. The original ISO is excluded;
only its filename and hashes are retained. Raw binary and
machine-readable evidence bytes are unchanged. Report Markdown was adapted to
make links portable and archive citations clickable on the web.

Original acquisition paths and snapshot line references in JSON/CSV/logs are
preserved as evidence, not changed to claim a different acquisition location.
The scripts are included as source; some historical reproduction scripts require
additional archive repositories or wiki/IRC snapshots from the original project.
Those external source archives are linked through SOURCES.md rather than copied
wholesale. The original project's full index is not a bundle dependency.

The ISO, extracted executables and source archives remain untrusted data. No
contained code was run during this copy. The original analysis and archives
remain in their existing locations.

The two large generated/extracted artifacts are stored using Git LFS. After
cloning, run `git lfs pull` to obtain their bytes. Their original hashes remain
in the evidence manifests. GitHub's [large-file documentation](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
describes the regular Git file limit.

The verification and publication manifest describe the published files.
Historical analysis verification reports under `output/iso-audit/` describe
the original analysis run, which had the matching ISO available locally.
