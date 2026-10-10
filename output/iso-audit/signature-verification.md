# OpenPGP signature and rootfs copy verification

A standard-library-only Python script parsed the armored key/message packets and checked the RSA signature mathematically. No extracted code or binary was executed; no external crypto package or system `gpg` was used.

## Signature result

- Signature valid: **True** using OpenPGP v4 canonical text, SHA-1 and RSA PKCS#1 v1.5.
- Signing public key fingerprint (v4 SHA-1): `6D854CD7933322A601C3286D181F01E57A35090F`; key ID `181F01E57A35090F`; user ID `Cicada 3301 (845145127)`.
- Signature creation time metadata: 2013-01-03T00:08:11+00:00 (signer-supplied).
- Canonical signed cleartext exactly matches `message.txt`: **False**. After removing one leading blank line from `message.txt`, the bytes match: **True**. This is presentation padding; visible text is unchanged.
- SHA-1 decoded from the RSA PKCS#1 encoded message: `2924ee8ba6fbd22fe98314e50193d51e6319b27f`.

A valid signature shows that the signed message verifies under the supplied public key. It does not independently authenticate the public key’s identity or provenance.

## Archive copy comparisons

SHA-256 hashes were compared for `cicada`, `prime_echo`, `message.txt`, `message.txt.asc`, `folly`, and `wisdom` against copies under neuroretransmit-cicada, archive2, and archive3 where present. The JSON records each located path and equality result.

- `usr/local/bin/cicada`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\usr\local\bin\cicada exact=False line-endings-normalized=True; archives\archive2\2013\additional files\Cicada OS\cicados\usr_local_bin\cicada exact=False line-endings-normalized=True; archives\archive2\assets\2013\cicados\usr_local_bin\cicada exact=False line-endings-normalized=True; archives\archive3\assets\2013\cicados\usr_local_bin\cicada exact=False line-endings-normalized=True
- `usr/local/bin/prime_echo`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\usr\local\bin\prime_echo exact=False line-endings-normalized=True; archives\archive2\2013\additional files\Cicada OS\cicados\usr_local_bin\prime_echo exact=False line-endings-normalized=True; archives\archive2\assets\2013\cicados\usr_local_bin\prime_echo exact=False line-endings-normalized=True; archives\archive3\assets\2013\cicados\usr_local_bin\prime_echo exact=False line-endings-normalized=True
- `usr/local/bin/message.txt`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\usr\local\bin\message.txt exact=False line-endings-normalized=True; archives\archive2\2013\additional files\Cicada OS\cicados\usr_local_bin\message.txt exact=False line-endings-normalized=True; archives\archive2\assets\2013\cicados\usr_local_bin\message.txt exact=False line-endings-normalized=True; archives\archive3\assets\2013\cicados\usr_local_bin\message.txt exact=False line-endings-normalized=True
- `usr/local/bin/message.txt.asc`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\usr\local\bin\message.txt.asc exact=False line-endings-normalized=True; archives\archive2\2013\additional files\Cicada OS\cicados\usr_local_bin\message.txt.asc exact=False line-endings-normalized=True; archives\archive2\assets\2013\cicados\usr_local_bin\message.txt.asc exact=False line-endings-normalized=True; archives\archive3\assets\2013\cicados\usr_local_bin\message.txt.asc exact=False line-endings-normalized=True
- `tmp/folly`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\tmp\folly exact=True line-endings-normalized=None; archives\archive2\2013\additional files\Cicada OS\cicados\tmp\folly exact=True line-endings-normalized=None; archives\archive2\assets\2013\cicados\tmp\folly exact=True line-endings-normalized=None; archives\archive3\assets\2013\cicados\tmp\folly exact=True line-endings-normalized=None
- `tmp/wisdom`: archives\neuroretransmit-cicada\2013\002-3301\rootfs-contents\tmp\wisdom exact=True line-endings-normalized=None; archives\archive2\2013\additional files\Cicada OS\cicados\tmp\wisdom exact=True line-endings-normalized=None; archives\archive2\assets\2013\cicados\tmp\wisdom exact=True line-endings-normalized=None; archives\archive3\assets\2013\cicados\tmp\wisdom exact=True line-endings-normalized=None

The signature verifier and full machine-readable results are in [codex-scripts/iso_signature_audit.py](../../codex-scripts/iso_signature_audit.py) and [output/iso-audit/signature-verification.json](signature-verification.json). Hash scope is limited to exact local paths present in the searched archive copies.
