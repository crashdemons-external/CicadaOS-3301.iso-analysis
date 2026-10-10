"""Static follow-up: provenance, builder sector, El Torito, kernel ELF and gzip metadata."""
from pathlib import Path
import hashlib, json, re, struct, zlib, datetime
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'output/iso-audit'
def h(b):return hashlib.sha256(b).hexdigest()
report={}
iso=(ROOT/'archives/3301.iso').read_bytes()
copies=[]
for name in ['archives/3301.iso','archives/archive1/2013/02/3301.iso','archives/archive2/assets/2013/3301','archives/archive3/assets/2013/3301']:
    b=(ROOT/name).read_bytes()
    x={'path':name,'size':len(b),'sha256':h(b),'matches_input':b==iso}
    if b.startswith(b'version https://git-lfs.github.com/spec/v1'):
        x['lfs_pointer']=b.decode();x['pointer_matches_input']=f'oid sha256:{h(iso)}' in b.decode() and f'size {len(iso)}' in b.decode()
    copies.append(x)
report['iso_copies']=copies
pvd=iso[16*2048:17*2048]
zone=int.from_bytes(pvd[829:830],'little',signed=True)*15
builddate=datetime.datetime.strptime(pvd[813:827].decode(),'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=zone)))
report['volume_creation']={'local_iso_metadata':builddate.isoformat(),'utc':builddate.astimezone(datetime.timezone.utc).isoformat(),'caveat':'Builder-supplied timestamp/timezone; not proof of creator location or authorship.'}
opaque=(OUT/'iso-files/DATA/560.13').read_bytes()
report['false_openpgp_magic']={'first_octet':hex(opaque[0]),'old_packet_tag':(opaque[0]>>2)&15,
    'length_type':opaque[0]&3,'declared_packet_body_length':int.from_bytes(opaque[1:5],'big'),
    'available_bytes_after_header':len(opaque)-5,'body_version_octet':opaque[5],
    'valid_complete_openpgp_key':False,'reason':'The accidental old-format tag-5 header declares more bytes than exist and the body starts with an invalid key version. A magic-byte match does not make this a secret key.'}
sector=iso[19*2048:20*2048];report['builder_sector']={'offset':19*2048,'printable_strings':[x.decode() for x in re.findall(rb'[ -~]{4,}',sector)],'nonzero':sum(x!=0 for x in sector),'sha256':h(sector)}
(OUT/'mkisofs-build-record.txt').write_text(sector.split(b'\x00')[0].decode()+'\n',encoding='utf-8')
catalog=(OUT/'iso-files/BOOT/ISOLINUX/BOOT.CAT').read_bytes()
bootloader=(OUT/'iso-files/BOOT/ISOLINUX/ISOLINUX.BIN').read_bytes()
report['el_torito']={'validation_checksum_mod_65536':sum(struct.unpack('<16H',catalog[:32]))%65536,
    'platform':catalog[1],'validation_key_hex':catalog[30:32].hex(),'bootable':catalog[32]==0x88,
    'media_type':catalog[33],'load_segment':int.from_bytes(catalog[34:36],'little'),
    'load_512_byte_sectors':int.from_bytes(catalog[38:40],'little'),
    'boot_image_lba':int.from_bytes(catalog[40:44],'little'),
    'bootloader_info_table':dict(zip(['pvd_lba','boot_lba','bootloader_length','checksum'],struct.unpack('<4I',bootloader[8:24]))),
    'loader_strings':[x.decode() for x in re.findall(rb'[ -~]{8,}',bootloader) if b'ISOLINUX' in x or b'Peter' in x]}
init=(OUT/'iso-files/BOOT/3301.IMG').read_bytes()
report['initramfs_gzip_header']={'magic':init[:3].hex(),'method':init[2],'flags':init[3],
    'mtime_unix':int.from_bytes(init[4:8],'little'),'extra_flags':init[8],'os_byte':init[9],
    'trailer_crc32':int.from_bytes(init[-8:-4],'little'),'trailer_isize':int.from_bytes(init[-4:],'little')}
kernel=(OUT/'iso-files/BOOT/VMLINUZ.').read_bytes()
offsets=[m.start() for m in re.finditer(b'\x1f\x8b\x08',kernel)]
report['kernel']={'size':len(kernel),'sha256':h(kernel),'gzip_offsets':offsets,
    'boot_header_magic':kernel[0x202:0x206].decode('ascii','replace'),
    'setup_sectors':kernel[0x1f1],
    'early_version_strings':[x.decode() for x in re.findall(rb'[ -~]{12,}',kernel[:18000]) if b'tinycore' in x]}
for offset in offsets:
    try:
        d=zlib.decompressobj(31); raw=d.decompress(kernel[offset:],64*1024*1024+1)
        if not d.eof or len(raw)>64*1024*1024:continue
        if not raw.startswith(b'\x7fELF'):continue
        (OUT/'kernel-vmlinux.elf').write_bytes(raw)
        assert raw[4]==1 and raw[5]==1
        hdr=struct.unpack('<HHIIIIIHHHHHH',raw[16:52])
        etype,machine,ver,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstrndx=hdr
        sections=[]
        assert shentsize==40 and shnum<1000
        for i in range(shnum):
            row=struct.unpack('<10I',raw[shoff+i*shentsize:shoff+(i+1)*shentsize]);sections.append(row)
        stringrow=sections[shstrndx];names=raw[stringrow[4]:stringrow[4]+stringrow[5]]
        named=[]
        accounted=shoff+shnum*shentsize
        for row in sections:
            name=names[row[0]:].split(b'\x00')[0].decode('ascii','replace')
            named.append({'name':name,'type':row[1],'offset':row[4],'size':row[5],'flags':row[2]})
            if row[1]!=8:accounted=max(accounted,row[4]+row[5])
        (OUT/'kernel-after-gzip.bin').write_bytes(d.unused_data)
        report['kernel'].update({'decompressed_size':len(raw),'decompressed_sha256':h(raw),
            'gzip_member_size':len(kernel)-offset-len(d.unused_data),
            'bytes_after_gzip':len(d.unused_data),'nonzero_after_gzip':sum(x!=0 for x in d.unused_data),
            'after_gzip_hex':d.unused_data[:100].hex(),'elf_machine':machine,'elf_entry':entry,
            'after_gzip_artifact':'output/iso-audit/kernel-after-gzip.bin',
            'after_gzip_caveat':'Nonzero bytes in the bzImage boot wrapper are not evidence of a hidden payload. No upstream stock-kernel byte comparison was performed.',
            'elf_sections':named,'elf_bytes_after_sections':len(raw)-accounted,
            'elf_nonzero_after_sections':sum(x!=0 for x in raw[accounted:]),
            'version_strings':[x.decode() for x in re.findall(rb'[ -~]{12,}',raw) if x.startswith(b'Linux version ')],
            'ikconfig_start_offset':raw.find(b'IKCFG_ST')})
        if raw.find(b'IKCFG_ST')>=0:
            start=raw.find(b'IKCFG_ST')+8;end=raw.find(b'IKCFG_ED',start)
            cfg=zlib.decompress(raw[start:end],31);(OUT/'kernel-config.txt').write_bytes(cfg)
        break
    except (zlib.error,ValueError,struct.error) as exc: report['kernel'].setdefault('errors',[]).append(str(exc))
(OUT/'structural-followup.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'builder':report['builder_sector']['printable_strings'],'boot':report['el_torito'],'kernel':{k:v for k,v in report['kernel'].items() if k!='elf_sections'}},indent=2))
