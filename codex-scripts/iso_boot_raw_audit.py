"""Read ISO structures as data; optionally fetch official loader baseline, never execute it."""
from pathlib import Path
import argparse, hashlib, json, struct, tarfile, urllib.request, zlib

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/iso-audit'
ISO=(ROOT/'archives/3301.iso').read_bytes()
BS=2048
def sha(b):return hashlib.sha256(b).hexdigest()
def summary(b):return {'size':len(b),'nonzero':sum(x!=0 for x in b),'sha256':sha(b)}
def differences(a,b):
    result=[];start=None
    for i in range(max(len(a),len(b))):
        unequal=i>=len(a) or i>=len(b) or a[i]!=b[i]
        if unequal and start is None:start=i
        if not unequal and start is not None:
            result.append({'start':start,'end_exclusive':i,'iso_hex':a[start:i].hex(),'baseline_hex':b[start:i].hex()});start=None
    if start is not None:result.append({'start':start,'end_exclusive':max(len(a),len(b)),'iso_hex':a[start:].hex(),'baseline_hex':b[start:].hex()})
    return result

parser=argparse.ArgumentParser();parser.add_argument('--download-baseline',action='store_true');args=parser.parse_args()
baseline=OUT/'boot-baseline';baseline.mkdir(exist_ok=True)
base='https://cdn.kernel.org/pub/linux/utils/boot/syslinux/3.xx/'
download_error=None
if args.download_baseline:
    try:
        for name,cap in [('syslinux-3.82.tar.gz',16*1024*1024),('sha256sums.asc',128*1024)]:
            p=baseline/name
            if not p.exists():
                with urllib.request.urlopen(base+name,timeout=30) as response:blob=response.read(cap+1)
                if len(blob)>cap:raise ValueError('Download exceeds size cap')
                p.write_bytes(blob)
    except (OSError,ValueError) as exc:download_error=str(exc)
archive=baseline/'syslinux-3.82.tar.gz'
baseline_info={'url':base+'syslinux-3.82.tar.gz','checksum_url':base+'sha256sums.asc','download_error':download_error,'comparison_available':False,'trust_limit':'Official HTTPS download and checksum comparison when available; detached OpenPGP signature not independently authenticated.'}
if archive.exists() and (baseline/'sha256sums.asc').exists():
    digest=sha(archive.read_bytes())
    matches=[x.split()[0] for x in (baseline/'sha256sums.asc').read_text().splitlines() if x.endswith('syslinux-3.82.tar.gz')]
    if len(matches)!=1 or matches[0]!=digest:raise ValueError('Official checksum mismatch')
    baseline_info.update({'package_size':archive.stat().st_size,'package_sha256':digest,'official_checksum_matches':True})
    with tarfile.open(archive,'r:gz') as t:
        for m in t:
            if m.name in ('syslinux-3.82/core/isolinux.bin','syslinux-3.82/core/isolinux.asm','syslinux-3.82/doc/isolinux.txt'):
                if not m.isfile() or m.size>1024*1024:raise ValueError('Unexpected baseline member')
                f=t.extractfile(m)
                if f is None:raise ValueError('Missing member data')
                (baseline/Path(m.name).name).write_bytes(f.read())

pvd=ISO[16*BS:17*BS];boot_record=ISO[17*BS:18*BS]
catalog_lba=int.from_bytes(boot_record[71:75],'little');catalog=ISO[catalog_lba*BS:(catalog_lba+1)*BS]
image_lba=int.from_bytes(catalog[40:44],'little')
loader=(OUT/'iso-files/BOOT/ISOLINUX/ISOLINUX.BIN').read_bytes()
table=dict(zip(('pvd_lba','boot_lba','file_length','checksum'),struct.unpack('<4I',loader[8:24])))
checksum=sum(int.from_bytes(loader[i:i+4].ljust(4,b'\0'),'little') for i in range(64,len(loader),4))&0xffffffff
inventory=json.loads((OUT/'iso-inventory.json').read_text())
loader_record=next(x for x in inventory if x['path']=='BOOT/ISOLINUX/ISOLINUX.BIN')
catalog_record=next(x for x in inventory if x['path']=='BOOT/ISOLINUX/BOOT.CAT')
kernel=(OUT/'iso-files/BOOT/VMLINUZ.').read_bytes()
setup_sects=kernel[0x1f1] or 4
protected_start=(setup_sects+1)*512
protected_size=int.from_bytes(kernel[0x1f4:0x1f8],'little')*16
payload_start=protected_start+int.from_bytes(kernel[0x248:0x24c],'little')
payload_length=int.from_bytes(kernel[0x24c:0x250],'little')
dec=zlib.decompressobj(31)
raw=dec.decompress(kernel[payload_start:payload_start+payload_length],64*1024*1024+1)
if len(raw)>64*1024*1024:raise ValueError('Kernel decompression size cap')
last_file=max(inventory,key=lambda x:x['extent']*BS+x['size'])
last_end=last_file['extent']*BS+last_file['size']
last_sector_end=(last_end+BS-1)//BS*BS
if (baseline/'isolinux.bin').exists():
    stock=(baseline/'isolinux.bin').read_bytes()
    masked=bytearray(loader);masked[8:64]=stock[8:64]
    baseline_info.update({'comparison_available':True,'baseline_loader_size':len(stock),'baseline_loader_sha256':sha(stock),'iso_loader_sha256':sha(loader),'diff_ranges':differences(loader,stock),'equal_outside_boot_info_table':bytes(masked)==stock})
signatures=[]
for sector in range(len(ISO)//BS):
    ident=ISO[sector*BS+1:sector*BS+6]
    if ident in (b'CD001',b'BEA01',b'NSR02',b'NSR03',b'TEA01'):
        signatures.append({'sector':sector,'type_byte':ISO[sector*BS],'identifier':ident.decode()})
result={
 'scope':'Raw ISO system area, El Torito records and loader metadata; no mounting or input-code execution.',
 'system_area':summary(ISO[:16*BS]),
 'sector_aligned_volume_signatures':signatures,
 'boot_record':{'sector':17,'boot_system_identifier_hex':boot_record[7:39].hex(),'boot_identifier':summary(boot_record[39:71]),'unused_after_catalog_pointer':summary(boot_record[75:]),'catalog_lba':catalog_lba},
 'catalog':{'lba':catalog_lba,'directory_lba':catalog_record['extent'],'directory_size':catalog_record['size'],'validation_header_id':catalog[0],'platform_id':catalog[1],'reserved_bytes_2_4_hex':catalog[2:4].hex(),'manufacturer_hex':catalog[4:28].hex(),'checksum_mod_65536':sum(struct.unpack('<16H',catalog[:32]))%65536,'validation_key_hex':catalog[30:32].hex(),'default_entry_hex':catalog[32:64].hex(),'default_entry_unused':summary(catalog[44:64]),'after_default_entry':summary(catalog[64:]),'bootable':catalog[32]==0x88,'media_type':catalog[33],'load_segment':int.from_bytes(catalog[34:36],'little'),'system_type':catalog[36],'unused_byte':catalog[37],'load_bytes':int.from_bytes(catalog[38:40],'little')*512,'image_lba':image_lba},
 'boot_info_table':{**table,'computed_checksum':checksum,'checksum_matches':checksum==table['checksum'],'reserved_24_64':summary(loader[24:64]),'pvd_pointer_matches':table['pvd_lba']==16,'catalog_and_directory_image_pointer_match':image_lba==table['boot_lba']==loader_record['extent'],'length_matches':table['file_length']==len(loader)==loader_record['size'],'loaded_bytes_match_file_prefix':ISO[image_lba*BS:image_lba*BS+int.from_bytes(catalog[38:40],'little')*512]==loader[:int.from_bytes(catalog[38:40],'little')*512]},
 'end_padding':{'last_directory_file':last_file['path'],'last_file_end_exclusive':last_end,'final_file_sector_slack':summary(ISO[last_end:last_sector_end]),'whole_sector_padding':summary(ISO[last_sector_end:]),'whole_padding_sectors':(len(ISO)-last_sector_end)//BS,'matches_150_sector_mkisofs_default':len(ISO)-last_sector_end==150*BS},
 'kernel_boot_header':{'protocol_version':hex(int.from_bytes(kernel[0x206:0x208],'little')),'setup_sects':setup_sects,'protected_code_start':protected_start,'protected_code_length_from_syssize':protected_size,'protected_code_end':protected_start+protected_size,'file_length_matches_header':protected_start+protected_size==len(kernel),'payload_start':payload_start,'payload_length':payload_length,'gzip_at_header_declared_offset':kernel[payload_start:payload_start+3]==b'\x1f\x8b\x08','declared_payload_is_exact_complete_gzip':dec.eof and not dec.unused_data and not dec.unconsumed_tail,'gzip_uncompressed_size':len(raw),'uncompressed_sha256':sha(raw),'matches_previously_carved_elf':raw==(OUT/'kernel-vmlinux.elf').read_bytes(),'remaining_wrapper_after_gzip':len(kernel)-payload_start-payload_length,'last4_little_endian':hex(int.from_bytes(kernel[-4:],'little')),'zlib_crc32_excluding_last4':hex(zlib.crc32(kernel[:-4])&0xffffffff),'last4_equals_complemented_zlib_crc32':int.from_bytes(kernel[-4:],'little')==((zlib.crc32(kernel[:-4])^0xffffffff)&0xffffffff),'zlib_crc32_entire_file':hex(zlib.crc32(kernel)&0xffffffff),'source':'https://www.kernel.org/doc/html/latest/arch/x86/boot.html','checksum_limit':'Convention corroborated by the saved upstream Linux v3.0 build.c and boot.txt; matching CRC is consistency, not authenticity.'},
 'baseline':baseline_info,
 'sources':['https://wiki.syslinux.org/wiki/index.php?title=ISOLINUX',base],
 'limits':'Checksums test internal consistency, not adversarial authenticity. No full matching Tiny Core baseline or runtime analysis.'
}
(OUT/'boot-raw-audit.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,indent=2))
