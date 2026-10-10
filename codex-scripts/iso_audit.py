"""Read-only bounded ISO9660 / gzip-newc CPIO audit. Never mounts or executes inputs.

Only regular files are extracted. Symlinks/device nodes remain manifest records.
Python stdlib only; paths, byte ranges, decompression size, and member counts bounded.
"""
from pathlib import Path, PurePosixPath
import collections, hashlib, json, math, stat, struct, zlib

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/iso-audit'
OUT.mkdir(parents=True, exist_ok=True)
ISO = ROOT / 'archives/3301.iso'
data = ISO.read_bytes()
BS = 2048
def hashes(b):
    return {n: hashlib.new(n, b).hexdigest() for n in ('md5', 'sha1', 'sha256')}
def save_json(name, obj):
    (OUT/name).write_text(json.dumps(obj, indent=2), encoding='utf-8')
def safe_path(base, name):
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in ('..', '') or ':' in x or '\\' in x for x in p.parts):
        raise ValueError('Unsafe path: '+repr(name))
    dest = base.joinpath(*p.parts)
    if not dest.resolve().is_relative_to(base.resolve()):
        raise ValueError('Escaping path')
    return dest
def extract(base, name, b):
    dest = safe_path(base, name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b)
def entropy(b):
    c = collections.Counter(b)
    return -sum((v/len(b))*math.log2(v/len(b)) for v in c.values()) if b else 0
def record(b, offset):
    n = b[offset]
    if not n or n < 34 or offset+n > len(b): raise ValueError('Invalid directory record')
    r = b[offset:offset+n]
    extent = int.from_bytes(r[2:6], 'little')
    size = int.from_bytes(r[10:14], 'little')
    if extent != int.from_bytes(r[6:10], 'big') or size != int.from_bytes(r[14:18], 'big'):
        raise ValueError('Endian field mismatch')
    ident = r[33:33+r[32]]
    ident_end=33+r[32]+(1 if r[32]%2==0 else 0)
    return {'extent':extent,'size':size,'flags':r[25], 'name':ident.decode('ascii', 'backslashreplace'),
            'extended_attribute_blocks':r[1],'file_unit_size':r[26],'interleave_gap_size':r[27],
            'volume_sequence_number':int.from_bytes(r[28:30],'little'),
            'system_use_hex':r[ident_end:].hex(),
            'date_raw':list(r[18:25]),'record_offset':offset,'record_hex':r.hex()}

descriptors=[]
for sector in range(16,80):
    d=data[sector*BS:(sector+1)*BS]
    if d[1:6] != b'CD001': raise ValueError('Invalid volume descriptor')
    descriptors.append({'sector':sector,'type':d[0],'sha256':hashes(d)['sha256']})
    if d[0]==1: pvd=d
    if d[0]==0:
        boot_catalog_lba=int.from_bytes(d[71:75], 'little')
    if d[0]==255: break
volume_size=int.from_bytes(pvd[80:84], 'little')*BS
inventory=[]
allocated=[(0,(sector+1)*BS,'system-area-and-volume-descriptors')]
for sizeoffset,lbaoffset,endian,label in [(132,140,'little','path-table-L'),(132,148,'big','path-table-M')]:
    size=int.from_bytes(pvd[sizeoffset:sizeoffset+4], 'little')
    lba=int.from_bytes(pvd[lbaoffset:lbaoffset+4], endian)
    allocated.append((lba*BS,lba*BS+size,label))
root_record=record(pvd,156)
seen=set()
def walk(rec, path=''):
    key=(rec['extent'],rec['size'])
    if key in seen: return
    seen.add(key)
    start=rec['extent']*BS
    end=start+rec['size']
    if end>len(data): raise ValueError('Directory outside ISO')
    allocated.append((start,end,'directory:'+path))
    i=start
    while i<end:
        if data[i]==0:
            i=(i//BS+1)*BS
            continue
        r=record(data,i); i+=data[i]
        if r['name'] in ('\x00','\x01'): continue
        name=r['name'].removesuffix(';1')
        full=path+'/'+name if path else name
        r['path']=full
        start_file=r['extent']*BS
        blob=data[start_file:start_file+r['size']]
        if len(blob)!=r['size']: raise ValueError('File outside ISO')
        if r['flags'] & 2: walk(r,full)
        else:
            if r['flags'] & 128: raise ValueError('Multi-extent file needs explicit handling')
            r.update(hashes(blob));r['entropy']=entropy(blob)
            r['first64_hex']=blob[:64].hex()
            allocated.append((start_file,start_file+r['size'],'file:'+full))
            extract(OUT/'iso-files',full,blob)
        inventory.append(r)
walk(root_record)

# Account for every byte outside metadata, directory and file extents, including slack.
allocated.sort()
gaps=[]; cursor=0
for start,end,label in allocated:
    if start>cursor:
        b=data[cursor:start]
        nz=[i for i,x in enumerate(b) if x]
        entry={'start':cursor,'end':start,'size':len(b),'nonzero':len(nz),
               'sha256':hashes(b)['sha256'],'first_nonzero':cursor+nz[0] if nz else None}
        if nz: extract(OUT/'unallocated',f'{cursor:09d}-{start:09d}.bin',b)
        gaps.append(entry)
    cursor=max(cursor,end)
if cursor<len(data):
    b=data[cursor:]; nz=sum(x!=0 for x in b)
    gaps.append({'start':cursor,'end':len(data),'size':len(b),'nonzero':nz,'sha256':hashes(b)['sha256']})
    if nz: extract(OUT/'unallocated',f'{cursor:09d}-{len(data):09d}.bin',b)
save_json('iso-inventory.json',inventory)
save_json('iso-layout.json',{'input':str(ISO),'size':len(data),**hashes(data),'descriptors':descriptors,
    'pvd_volume_size':volume_size,'system_id':pvd[8:40].decode().strip(),
    'volume_id':pvd[40:72].decode().strip(),'application_id':pvd[574:702].decode().strip(),
    'timestamps_raw':[pvd[i:i+17].hex() for i in (813,830,847,864)],
    'boot_catalog_lba':boot_catalog_lba,'allocated_ranges':allocated,'gaps':gaps,
    'system_area_nonzero':sum(x!=0 for x in data[:16*BS])})

compressed=(OUT/'iso-files/BOOT/3301.IMG').read_bytes()
dec=zlib.decompressobj(31)
cpio=dec.decompress(compressed,128*1024*1024+1)
if len(cpio)>128*1024*1024 or not dec.eof: raise ValueError('Decompression limit / truncated gzip')
extract(OUT,'initramfs.cpio',cpio)
entries=[]; pos=0; payload_ranges=[]
while pos<len(cpio) and len(entries)<20000:
    while pos<len(cpio) and cpio[pos]==0: pos+=1
    if pos==len(cpio): break
    start=pos
    if cpio[pos:pos+6] not in (b'070701',b'070702'): raise ValueError('Unsupported CPIO at '+str(pos))
    fields=[int(cpio[pos+6+i*8:pos+14+i*8],16) for i in range(13)]
    ino,mode,uid,gid,nlink,mtime,size,devmajor,devminor,rdevmajor,rdevminor,namesize,check=fields
    if namesize<1 or namesize>4096: raise ValueError('Invalid CPIO name')
    name=cpio[pos+110:pos+110+namesize-1].decode('utf-8','backslashreplace')
    if cpio[pos+110+namesize-1]!=0: raise ValueError('Unterminated CPIO name')
    pos=(pos+110+namesize+3)&~3
    end=pos+size
    if end>len(cpio):raise ValueError('CPIO outside decompressed buffer')
    blob=cpio[pos:end]
    e={'path':name,'header_offset':start,'data_offset':pos,'size':size,'ino':ino,
       'format':cpio[start:start+6].decode(),'name_size_with_nul':namesize,'checksum_field':check,
       'header_hex':cpio[start:start+110].hex(),
       'mode':oct(mode),'uid':uid,'gid':gid,'nlink':nlink,'mtime':mtime,
       'dev':[devmajor,devminor],'rdev':[rdevmajor,rdevminor],**hashes(blob)}
    if stat.S_ISREG(mode):
        safe_name=name.removeprefix('./')
        extract(OUT/'rootfs',safe_name,blob)
        e['type']='regular';payload_ranges.append((pos,end,name))
    elif stat.S_ISLNK(mode): e['type']='symlink';e['target']=blob.decode('utf-8','backslashreplace')
    elif stat.S_ISDIR(mode):e['type']='directory'
    else:e['type']='special'
    entries.append(e)
    pos=(end+3)&~3
    if name=='TRAILER!!!':break
save_json('rootfs-manifest.json',entries)
save_json('compression.json',{'compressed_size':len(compressed),'decompressed_size':len(cpio),
    'gzip_unused_size':len(dec.unused_data),'gzip_unused_hex':dec.unused_data[:100].hex(),
    'cpio_trailer_end':pos,'cpio_after_trailer_size':len(cpio)-pos,
    'cpio_after_trailer_nonzero':sum(x!=0 for x in cpio[pos:]),'entries':len(entries)})
print(json.dumps({'iso_hashes':hashes(data),'files':len(inventory),'gap_nonzero':sum(g['nonzero'] for g in gaps),
    'rootfs_entries':len(entries),'rootfs_bytes':len(cpio),'gzip_tail':len(dec.unused_data),'cpio_tail_nonzero':sum(x!=0 for x in cpio[pos:])},indent=2))
