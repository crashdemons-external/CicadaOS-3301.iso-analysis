# Follow-up: stream relationships and direct reconstruction

Scope: standard-library static byte operations only. No archive scripts or ISO executables were run. Script: [codex-scripts/iso_data_followup.py](../../codex-scripts/iso_data_followup.py); complete histograms, same-folder `.rev` checks, lengths, and search results are recorded in [output/iso-audit/data-followup.json](data-followup.json).

The extracted `folly` and `wisdom` are byte-identical (3,368 bytes). Their byte histogram contains every possible byte value; Shannon entropy is 7.937666 bits/byte (maximum 8), and Pearson's uniform-bin chi-square statistic is 277.568 with 255 degrees of freedom (each expected bin count is 13.156). These summary statistics show a near-uniform byte distribution, but do not identify the encoding or establish that the stream is encrypted. Their lengths factor as `2^3 × 421`.

Neither full file, its complete byte reversal, nor forward or reversed prefixes of 64, 256, or 1,024 bytes occur in extracted `560.13`, `560.17`, `_560.00`, or `761.MP3`. The three extracted DATA files also have distinct first 64 bytes; each DATA file's 64-byte prefix occurs nowhere in either of the other two DATA streams. This rules out the tested direct contiguous reuse, not transformed or offset-dependent relationships.

The full data/audio file lengths factor as follows: `560.13` = 118,818,811 (prime by trial division through its square root); `560.17` = 1,183,811 (prime); `_560.00` = `2 × 3 × 5 × 167 × 797`; and `761.MP3` = `2^2 × 11 × 91,153`. These are byte counts and do not on their own imply puzzle meaning.

A fresh reconstruction from all 988 offset/hex records in `tweets/full.txt` produces a 64,167-byte [twitter-rebuilt.bin](twitter-rebuilt.bin) identical to archived `twitter.bin` (SHA-256 `defa1176…ce3776`). This validates the raw tweet dump to binary reconstruction independently of the saved binary artifact.

Within same-directory `.rev` pairs, all complete file pairs checked are literal byte reversals. The only non-reversing pairs are the two 137-byte `560.13` Git LFS pointer pairs in archive2; the full archive3 `560.13.rev` is a literal reversal. Checks use only each `.rev` file's sibling with its `.rev` suffix removed, avoiding cross-archive pairing ambiguity.
