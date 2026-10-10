# ISO9660 file extents and metadata

ISO9660 has no intrinsic Unix inode, uid/gid or POSIX mode in these records. This ISO has no Rock Ridge/Joliet descriptors or system-use POSIX fields. Block/extents and directory-record offsets are physical identifiers; host-extraction inode numbers are irrelevant. Recorded timestamps are builder-supplied modification times, not birth/creation evidence.

| File | LBA | Size | Recorded timestamp | Directory record offset |
|---|---:|---:|---|---:|
| `AUDIO/761.MP3` | 37 | 4010732 | 2013-01-03T22:29:26-05:00 | 51268 |
| `BOOT/3301.IMG` | 62542 | 5494774 | 2013-01-03T23:18:37-05:00 | 55364 |
| `BOOT/ISOLINUX/BOOT.CAT` | 29 | 2048 | 2013-01-03T23:19:55-05:00 | 57412 |
| `BOOT/ISOLINUX/ISOLINUX.BIN` | 30 | 14336 | 2013-01-03T23:18:40-05:00 | 57456 |
| `BOOT/ISOLINUX/ISOLINUX.CFG` | 66442 | 214 | 2012-12-24T01:31:49-05:00 | 57504 |
| `BOOT/ISOLINUX/ISOLINUX.TXT` | 66443 | 12 | 2012-12-24T01:31:49-05:00 | 57552 |
| `BOOT/ISOLINUX/SPLASH.RLE` | 66444 | 14120 | 2013-01-02T18:13:18-05:00 | 57600 |
| `BOOT/VMLINUZ.` | 65225 | 2491968 | 2012-12-24T01:31:49-05:00 | 55450 |
| `DATA/560.13` | 1996 | 118818811 | 2013-01-03T23:14:57-05:00 | 53316 |
| `DATA/560.17` | 60013 | 1183811 | 2013-01-02T20:22:10-05:00 | 53358 |
| `DATA/_560.00` | 60592 | 3992970 | 2013-01-03T23:19:32-05:00 | 53400 |

Full raw identifiers, flags, hashes, attributes, byte offsets and UTC conversions are in the adjacent JSON/TSV. Files identified as author-supplied puzzle assets include AUDIO/761.MP3, DATA/*, and BOOT/ISOLINUX/SPLASH.RLE; the initramfs contains both stock and custom files. The loader, kernel and configuration are inventoried without asserting individual authorship.
