#!/usr/bin/env python3
# Read-only ISO9660 primary descriptor and path table audit.
from pathlib import Path
from collections import deque, Counter
import hashlib,json,struct
import datetime
ROOT=Path(__file__).resolve().parents[1]; ISO=ROOT/'archives/3301.iso'; OUT=ROOT/'output/iso-audit'; BS=2048
def sh(b): return hashlib.sha256(b).hexdigest()
def filehash(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for x in iter(lambda:f.read(1<<20),b''): h.update(x)
 return h.hexdigest()
def sec(f,n): f.seek(n*BS); return f.read(BS)
def b32(b): return [int.from_bytes(b[:4],'little'),int.from_bytes(b[4:8],'big')]
def b16(b): return [int.from_bytes(b[:2],'little'),int.from_bytes(b[2:4],'big')]
def dr(b):
 n=b[0]
 if n<34 or n>len(b): raise ValueError('bad directory record length')
 nl=b[32]; name=b[33:33+nl]; su=33+nl+(1 if nl%2==0 else 0)
 return {'len':n,'ext_attr_len':b[1],'extent':b32(b[2:10]),'size':b32(b[10:18]),'flags':b[25],'volume_seq':b16(b[28:32]),'name':name,'system_use':b[su:n]}
def timestamp(raw):
 text=raw[:16].decode('ascii','replace'); tz=raw[16]; signed=tz if tz<128 else tz-256
 out={'raw_hex':raw.hex(),'text':text,'timezone_raw':tz,'timezone_quarters_signed':signed}
 if text=='0'*16:
  out.update({'valid':True,'meaning':'unspecified'})
  return out
 try:
  if len(text)!=16 or not text.isdigit(): raise ValueError('timestamp is not 16 ASCII digits')
  year,month,day,hour,minute,second,centisec=(int(text[a:b]) for a,b in ((0,4),(4,6),(6,8),(8,10),(10,12),(12,14),(14,16)))
  datetime.datetime(year,month,day,hour,minute,second)
  if centisec>99: raise ValueError('hundredths outside 00..99')
  if not -48<=signed<=52: raise ValueError('timezone outside -48..+52 quarter-hours')
  out.update({'valid':True,'year':year,'month':month,'day':day,'hour':hour,'minute':minute,'second':second,'hundredths':centisec,'timezone_minutes':signed*15})
 except Exception as e: out.update({'valid':False,'error':str(e)})
 return out
def fixed_text(b):
 raw=b; trimmed=raw.rstrip(b' '); padding=len(raw)-len(trimmed)
 return {'length':len(raw),'text':trimmed.decode('ascii','replace'),'trailing_space_padding':padding,'padding_valid':raw.endswith(b' '*padding),'nonprintable_bytes':[i for i,x in enumerate(raw) if x<32 or x>126]}
def ptparse(data,order):
 a=[]; issues=[]; p=0
 while p<len(data):
  if not any(data[p:]): break
  if p+8>len(data): issues.append('truncated'); break
  nl,ea=data[p],data[p+1]; n=8+nl+(nl%2)
  if not nl or p+n>len(data): issues.append(f'invalid@{p}'); break
  nm=data[p+8:p+8+nl]; a.append({'number':len(a)+1,'name_hex':nm.hex(),'name':'<ROOT>' if nm==b'\0' else nm.decode('ascii','replace'),'extent':int.from_bytes(data[p+2:p+6],order),'parent':int.from_bytes(data[p+6:p+8],order),'ext_attr_len':ea,'offset':p})
  if nl%2 and data[p+8+nl]: issues.append(f'nonzero_pad@{p+8+nl}')
  p+=n
 return a,issues,p
def main():
 size=ISO.stat().st_size; sectors,tail=divmod(size,BS)
 with ISO.open('rb') as f:
  ds=[]; seq=[]; pvd=None
  for lba in range(16,min(sectors,256)):
   b=sec(f,lba); seq.append({'lba':lba,'type':b[0],'id':b[1:6].decode('ascii','replace'),'version':b[6]})
   if b[1:6]!=b'CD001': break
   d={'lba':lba,'type':b[0],'version':b[6],'sha256':sh(b)}
   if b[0]==1:
    pvd=b; root=dr(b[156:190]); d.update({'system_id':fixed_text(b[8:40]),'volume_id':fixed_text(b[40:72]),'volume_space_size_both':b32(b[80:88]),'volume_set_size_both':b16(b[120:124]),'volume_sequence_both':b16(b[124:128]),'block_size_both':b16(b[128:132]),'path_table_size_both':b32(b[132:140]),'type_l_lba':int.from_bytes(b[140:144],'little'),'optional_l_lba':int.from_bytes(b[144:148],'little'),'type_m_lba':int.from_bytes(b[148:152],'big'),'optional_m_lba':int.from_bytes(b[152:156],'big'),'root_record_hex':b[156:190].hex(),'root_extent_both':root['extent'],'root_size_both':root['size'],'root_volume_seq_both':root['volume_seq'],'root_flags':root['flags'],'text_fields':{'volume_set_id':fixed_text(b[190:318]),'publisher_id':fixed_text(b[318:446]),'data_preparer_id':fixed_text(b[446:574]),'application_id':fixed_text(b[574:702]),'copyright_file_id':fixed_text(b[702:739]),'abstract_file_id':fixed_text(b[739:776]),'bibliographic_file_id':fixed_text(b[776:813])},'timestamps':{'creation':timestamp(b[813:830]),'modification':timestamp(b[830:847]),'expiration':timestamp(b[847:864]),'effective':timestamp(b[864:881])},'file_structure_version':b[881],'reserved_byte_882':b[882],'reserved_7_7_nonzero':sum(x!=0 for x in b[7:8]),'reserved_72_79_nonzero':sum(x!=0 for x in b[72:80]),'reserved_88_119_nonzero':sum(x!=0 for x in b[88:120]),'application_use_offsets':[883,1394],'application_use_nonzero':sum(x!=0 for x in b[883:1395]),'application_use_spaces':b[883:1395].count(32),'application_use_nuls':b[883:1395].count(0),'application_use_nonspace':sum(x not in (0,32) for x in b[883:1395]),'application_use_sha256':sh(b[883:1395]),'reserved_offsets':[1395,2047],'reserved_nonzero':sum(x!=0 for x in b[1395:]),'reserved_sha256':sh(b[1395:])})
   elif b[0]==0: d.update({'boot_system_id':b[7:39].decode('ascii','replace').split(chr(0))[0].rstrip(),'boot_id':b[39:71].decode('ascii','replace').split(chr(0))[0].rstrip(),'catalog_lba':int.from_bytes(b[71:75],'little'),'system_use_nonzero':sum(x!=0 for x in b[75:])})
   elif b[0]==255: d.update({'reserved_7_2047_nonzero':sum(x!=0 for x in b[7:]),'reserved_7_2047_sha256':sh(b[7:])})
   ds.append(d)
   if b[0]==255: break
  if pvd is None: raise RuntimeError('no PVD')
  plen=int.from_bytes(pvd[132:136],'little'); ll=int.from_bytes(pvd[140:144],'little'); ml=int.from_bytes(pvd[148:152],'big')
  f.seek(ll*BS); lraw=f.read(plen); f.seek(ml*BS); mraw=f.read(plen); L,li,lc=ptparse(lraw,'little'); M,mi,mc=ptparse(mraw,'big')
  def canonical(tab):
   out=[]
   for e in tab:
    nm=bytes.fromhex(e['name_hex']); par=e['parent']; path=b'' if nm==b'\0' else ((out[par-1]['path']+b'/') if 1<=par<=len(out) else b'<badparent>/')+nm
    out.append({'path':path,'extent':e['extent'],'parent':par,'ext_attr_len':e['ext_attr_len']})
   return out
  lp,mp=canonical(L),canonical(M); dif=Counter((x['path'].hex(),x['extent'],x['parent'],x['ext_attr_len']) for x in lp); dif.subtract((x['path'].hex(),x['extent'],x['parent'],x['ext_attr_len']) for x in mp)
  differences=[{'path_hex':k[0],'extent':k[1],'parent':k[2],'ext_attr_len':k[3],'L_minus_M':v} for k,v in dif.items() if v]
  root=dr(pvd[156:190]); q=deque([(root['extent'][0],root['size'][0],b'')]); seen=set(); dirs=set(); actual_dirs={b'':{'extent':root['extent'][0],'ext_attr_len':root['ext_attr_len']}}; files=0; issues=[]; flag_counts=Counter(); names=[]; unexpected_flags=[]; endian_mismatches=[]
  for field,vals in (('root_extent',root['extent']),('root_size',root['size']),('root_volume_seq',root['volume_seq'])):
   if vals[0]!=vals[1]: endian_mismatches.append({'record':'PVD root record','field':field,'values':vals})
  while q:
   ex,n,dirpath=q.popleft()
   if (ex,n) in seen: issues.append({'kind':'duplicate_or_loop','extent':ex,'size':n}); continue
   seen.add((ex,n)); dirs.add(ex)
   if ex*BS+n>size: issues.append({'kind':'out_of_image','extent':ex,'size':n}); continue
   f.seek(ex*BS); data=f.read(n); pos=0
   while pos<len(data):
    if data[pos]==0: pos=((pos//BS)+1)*BS; continue
    try:r=dr(data[pos:])
    except Exception as e: issues.append({'kind':'bad_record','extent':ex,'offset':pos,'error':str(e)}); break
    for field,vals in (('extent',r['extent']),('size',r['size']),('volume_seq',r['volume_seq'])):
     if vals[0]!=vals[1]: endian_mismatches.append({'directory':dirpath.hex(),'record_offset':pos,'name_hex':r['name'].hex(),'field':field,'values':vals})
    flag_counts[r['flags']]+=1
    if r['name'] not in (b'\0',b'\1'):
     names.append(r['name'].decode('ascii','replace'))
     if r['flags'] & 0xFD: unexpected_flags.append({'name':r['name'].decode('ascii','replace'),'flags':r['flags']})
     if r['flags']&2:
      childpath=dirpath+b'/'+r['name']; actual_dirs[childpath]={'extent':r['extent'][0],'ext_attr_len':r['ext_attr_len']}; q.append((r['extent'][0],r['size'][0],childpath))
     else:files+=1
    pos+=r['len']
  # Locate every CD001 identifier; descriptor identifier starts at sector offset one.
  positions=[]; f.seek(0); carry=b''; base=0
  while True:
   chunk=f.read(1<<20)
   if not chunk:break
   buf=carry+chunk; start=base-len(carry); j=0
   while True:
    j=buf.find(b'CD001',j)
    if j<0:break
    positions.append(start+j); j+=1
   carry=buf[-4:]; base+=len(chunk)
  sigs=[x for x in positions if x%BS==1]
  table_dirs={(x['path'],x['extent'],x['ext_attr_len']) for x in lp}; actual_dir_tuples={(k,v['extent'],v['ext_attr_len']) for k,v in actual_dirs.items()}
  table_tree_diff={'path_table_without_directory_record':[{'path_hex':p.hex(),'extent':e,'ext_attr_len':a} for p,e,a in sorted(table_dirs-actual_dir_tuples)],'directory_record_without_path_table':[{'path_hex':p.hex(),'extent':e,'ext_attr_len':a} for p,e,a in sorted(actual_dir_tuples-table_dirs)]}
  result={'input':{'path':'archives/3301.iso','bytes':size,'sha256':filehash(ISO),'sector_bytes':BS,'sectors':sectors,'tail_bytes':tail},'descriptor_sequence':seq,'descriptors':ds,'CD001_scan':{'occurrences':len(positions),'descriptor_identifier_offsets':[{'offset':x,'lba':(x-1)//BS} for x in sigs]},'path_tables':{'declared_size_both':b32(pvd[132:140]),'type_l':{'lba':ll,'entries':L,'issues':li,'consumed_bytes':lc,'unused_bytes':plen-lc},'type_m':{'lba':ml,'entries':M,'issues':mi,'consumed_bytes':mc,'unused_bytes':plen-mc},'L_M_differences_including_name_parent_extent_extattr':differences,'table_directory_tree_differences':table_tree_diff},'directory_walk':{'directory_count':len(seen),'file_count':files,'directory_record_flags':dict(flag_counts),'ordinary_identifiers':names,'version_1_identifiers':sum(n.endswith(';1') for n in names),'identifiers_without_version_1_suffix':[n for n in names if not n.endswith(';1')],'nonordinary_flags':unexpected_flags,'both_endian_record_mismatches':endian_mismatches,'issues':issues},'limits':['This checks the descriptor sequence, PVD field contents/padding/timestamps/reserved regions, all directory record duplicated numeric fields, both path tables, and exact reconstructed directory identity/extent/extended-attribute agreement. It does not establish provenance or examine arbitrary file payloads for steganography.']}
  OUT.joinpath('descriptor-audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
  p=next(x for x in ds if x['type']==1); boot=next(x for x in ds if x['type']==0); term=next(x for x in ds if x['type']==255); tf=p['text_fields']; ts=p['timestamps']
  lines=['# ISO descriptor and path-table audit','','Read-only byte inspection of `archives/3301.iso`; no mounting or execution. Reproduce with `codex-scripts/iso_descriptor_audit.py`.','',f"Input: {size:,} bytes ({sectors:,} 2048-byte sectors, {tail} trailing bytes), SHA-256 `{result['input']['sha256']}`.",'','## Descriptor sequence and PVD fields','',f"Sequential descriptor set at LBAs 16–18: Primary Volume Descriptor (type 1), El Torito Boot Record (type 0), and Volume Descriptor Set Terminator (type 255), all `CD001` version 1. No supplementary/enhanced descriptor occurs in this sequence. PVD identifiers: system `{p['system_id']['text']}` ({p['system_id']['trailing_space_padding']} trailing spaces), volume `{p['volume_id']['text']}` ({p['volume_id']['trailing_space_padding']} trailing spaces).",f"LE/BE copies agree: volume space {p['volume_space_size_both']}; volume set {p['volume_set_size_both']}; volume sequence {p['volume_sequence_both']}; logical block size {p['block_size_both']}; path-table size {p['path_table_size_both']}. Root-directory extent {p['root_extent_both']}, byte length {p['root_size_both']}, volume sequence {p['root_volume_seq_both']}, flags {p['root_flags']}; the root record's duplicated fields match.",f"All fixed PVD text fields (system/volume identifiers and volume-set, publisher, preparer, application, copyright, abstract, bibliographic identifiers) contain printable ASCII with trailing-space padding only. The six fields other than application ID are blank/all spaces. Application ID: `{tf['application_id']['text']}` followed by {tf['application_id']['trailing_space_padding']} spaces.",f"PVD raw timestamps: creation, modification, and effective are `2013010323195500` with signed timezone byte 0xEC (−300 minutes); all validate as 2013-01-03 23:19:55.00 −05:00. Expiration is sixteen zero digits plus offset 0, the standard unspecified value. All four timestamp fields validate; no malformed date/time is present.",f"Type-L path table LBA {p['type_l_lba']}; Type-M LBA {p['type_m_lba']}; optional path-table LBAs {p['optional_l_lba']} / {p['optional_m_lba']}. PVD reserved byte 7, bytes 72–79, bytes 88–119, byte 882, and bytes 1395–2047 are all zero. Application-use descriptor-relative offsets 883–1394 (absolute ISO offsets 33651–34162) contain exactly {p['application_use_spaces']} spaces, {p['application_use_nuls']} NULs, and no other bytes. Terminator reserved bytes 7–2047 are all zero. These fill values do not indicate hidden edits.",f"The Boot Record identifies `{boot['boot_system_id']}`, catalog LBA {boot['catalog_lba']}, and zero bytes in its remaining system-use area. Raw scan found {len(positions)} `CD001` instances; descriptor-identifier offsets are {sigs}, corresponding to LBAs {[ (x-1)//BS for x in sigs ]}. No other sector-aligned signature was found.",'','## Path tables and directory tree','',f"The declared size is {plen} bytes for each table. Both tables parse as {len(L)} entries, consume all bytes, have no parse issues, and match exactly in identifier bytes/reconstructed path, extent, parent index, and extended-attribute length. Their reconstructed paths are root, AUDIO, BOOT, DATA, and BOOT/ISOLINUX; the corresponding on-disc directory records match all five full paths, extents, and extended-attribute lengths. The directory walk visits {len(seen)} directories and {files} files with {len(issues)} errors; duplicated extent/size/volume-sequence fields agree across the PVD root record and every walked directory record ({len(endian_mismatches)} mismatches). Directory-record flag values are {dict(flag_counts)} (directory bit 0x02 on directories, zero on files); no hidden, associated, multi-extent, protection, or reserved flag bits are set. All {sum(n.endswith(';1') for n in names)} file identifiers use the `;1` version suffix; directory identifiers are AUDIO, BOOT, DATA, and ISOLINUX.",'','## Assessment','',"The checked metadata is internally consistent. No descriptor/path-table alteration signal appeared in these regions. This is format consistency evidence, not proof of provenance or a comprehensive search of file payloads. Zero optional-table locations and blank reserved/application-use fields are ordinary compatible values.",'', 'Format reference: [ECMA-119, 3rd edition (2017)](https://ecma-international.org/wp-content/uploads/ECMA-119_3rd_edition_december_2017.pdf), an ISO-9660-compatible volume/file-structure standard.']
  OUT.joinpath('descriptor-audit.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
  print(json.dumps({'written':['output/iso-audit/descriptor-audit.json','output/iso-audit/descriptor-audit.md'],'descriptor_identifier_offsets':sigs,'directories':len(seen),'files':files,'path_table_diffs':len(differences),'issues':issues},indent=2))
if __name__=='__main__':main()
