# 2013 phone ciphertext and offset XOR audit

This report applies only documented ciphertext bytes to the already extracted ISO DATA files. It does not call phone numbers or visit onion services. The reproducible standard-library script is [codex-scripts/phone_xor_audit.py](../../codex-scripts/phone_xor_audit.py); row-by-row ciphertext, plaintext, and diagnostic recovered ciphertext are in [output/iso-audit/phone-xor-audit.json](phone-xor-audit.json).

All four unambiguous dataset-13 entries decrypt exactly to their documented onion plus a trailing line feed: Okinawa at 37,861, Moscow at 1,111,111, Little Rock at 13,831, Portland at 12,821. The dataset-17 Columbus entry at 617 also matches. Dallas decrypts to `y2wyuvrqraowagc5.onion\n` at offset 33,461. The alternate offset 16,433 printed in the wiki does not decrypt to the expected onion; XORing the 16,433 window with the known expected onion plus LF produces a different ciphertext from the supplied one. This supports the archive3 README's 33,461 correction and identifies the wiki offset as an early transcription.

The README's Annapolis ciphertext at offset 77,977 is malformed and decrypts to a partly readable but invalid string. The corrected wiki ciphertext from export line 34685 decrypts exactly to `erwfcsdvx6pm2rsk.onion\n`. Re-XORing the ISO window with that known expected plaintext reproduces the corrected wiki ciphertext byte for byte. This is a source transcription repair, not a new puzzle result.

These checks verify that both extracted datasets are needed: the dataset-17 rows match `560.17`, corroborating its later documented use alongside dataset 13. All outcomes remain byte-level consistency checks against the archived records, not independent authentication of the ISO's provenance.


