"""Record ISO9660 physical identifiers and times without inventing Unix inodes."""
from pathlib import Path
import csv, datetime, json
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'output/iso-audit'
inventory=json.loads((OUT/'iso-inventory.json').read_text())
rows=[]
for e in inventory:
    if e['flags']&2:continue
    y,m,d,hh,mm,ss,offset=e['date_raw'];offset=offset if offset<128 else offset-256
    dt=datetime.datetime(1900+y,m,d,hh,mm,ss,tzinfo=datetime.timezone(datetime.timedelta(minutes=offset*15)))
    rows.append({'path':e['path'],'raw_identifier':e['name'],'logical_block':e['extent'],
        'absolute_data_offset':e['extent']*2048,'size':e['size'],'directory_record_offset':e['record_offset'],
        'record_flags':e['flags'],'timestamp_recorded':dt.isoformat(),'timestamp_utc':dt.astimezone(datetime.timezone.utc).isoformat(),
        'sha256':e['sha256'],'extended_attribute_blocks':e['extended_attribute_blocks'],
        'system_use_hex':e['system_use_hex'],'file_unit_size':e['file_unit_size'],'interleave_gap_size':e['interleave_gap_size'],
        'volume_sequence_number':e['volume_sequence_number']})
note='ISO9660 has no intrinsic Unix inode, uid/gid or POSIX mode in these records. This ISO has no Rock Ridge/Joliet descriptors or system-use POSIX fields. Block/extents and directory-record offsets are physical identifiers; host-extraction inode numbers are irrelevant. Recorded timestamps are builder-supplied modification times, not birth/creation evidence.'
(OUT/'iso-extent-metadata.json').write_text(json.dumps({'scope':note,'files':rows},indent=2),encoding='utf-8')
with (OUT/'iso-extent-metadata.tsv').open('w',newline='',encoding='utf-8') as f:
    writer=csv.DictWriter(f,fieldnames=list(rows[0]),delimiter='\t');writer.writeheader();writer.writerows(rows)
md='# ISO9660 file extents and metadata\n\n'+note+'\n\n| File | LBA | Size | Recorded timestamp | Directory record offset |\n|---|---:|---:|---|---:|\n'
for r in rows:md+=f"| `{r['path']}` | {r['logical_block']} | {r['size']} | {r['timestamp_recorded']} | {r['directory_record_offset']} |\n"
md+='\nFull raw identifiers, flags, hashes, attributes, byte offsets and UTC conversions are in the adjacent JSON/TSV. Files identified as author-supplied puzzle assets include AUDIO/761.MP3, DATA/*, and BOOT/ISOLINUX/SPLASH.RLE; the initramfs contains both stock and custom files. The loader, kernel and configuration are inventoried without asserting individual authorship.\n'
(OUT/'iso-extent-metadata.md').write_text(md,encoding='utf-8')
print('Recorded',len(rows),'ISO files')
