from pathlib import Path
import hashlib, json, math, datetime

ROOT=Path(__file__).resolve().parents[1]
ISO_PATH=ROOT/'archives/3301.iso'
OUT=ROOT/'output/iso-audit'
BLOCK=2048
raw=ISO_PATH.read_bytes()

def both16(b,o): return {'le':int.from_bytes(b[o:o+2],'little'),'be':int.from_bytes(b[o+2:o+4],'big'),'raw_hex':b[o:o+4].hex()}
def both32(b,o): return {'le':int.from_bytes(b[o:o+4],'little'),'be':int.from_bytes(b[o+4:o+8],'big'),'raw_hex':b[o:o+8].hex()}
def root_record(b,o):
    n=b[o]
    return parse_record(b[o:o+n],o) if n>=34 and o+n<=len(b) else None

def parse_record(rec,absolute_offset):
    n=rec[0]; idlen=rec[32]; idstart=33; idend=idstart+idlen
    pad_len=1 if idlen%2==0 else 0
    su_start=idend+pad_len
    raw_id=rec[idstart:idend]
    if raw_id==b'\0': ident='.'
    elif raw_id==b'\1': ident='..'
    else: ident=raw_id.decode('ascii','replace')
    dt=rec[18:25]
    date_parts={'year':1900+dt[0],'month':dt[1],'day':dt[2],'hour':dt[3],'minute':dt[4],'second':dt[5],'timezone_quarters_signed':dt[6]-256 if dt[6]>127 else dt[6]}
    try:
        datetime.datetime(date_parts['year'],date_parts['month'],date_parts['day'],date_parts['hour'],date_parts['minute'],date_parts['second'])
        date_valid=-48<=date_parts['timezone_quarters_signed']<=52
    except ValueError:
        date_valid=False
    return {'absolute_offset':absolute_offset,'record_length':n,'xar_length':rec[1],
      'extent':both32(rec,2),'data_length':both32(rec,10),
      'recording_date_raw':dt.hex(),'recording_date_parts':date_parts,'recording_date_valid':date_valid,'flags':rec[25],
      'flag_bits':{'hidden':bool(rec[25]&1),'directory':bool(rec[25]&2),'associated':bool(rec[25]&4),'record_format':bool(rec[25]&8),'permissions':bool(rec[25]&16),'multi_extent':bool(rec[25]&128)},
      'file_unit_size':rec[26],'interleave_gap_size':rec[27],
      'volume_sequence':both16(rec,28),'file_identifier_length':idlen,
      'identifier_bytes_hex':raw_id.hex(),'identifier':ident,
      'padding_length':pad_len,'padding_hex':rec[idend:su_start].hex(),
      'system_use_length':n-su_start,'system_use_hex':rec[su_start:n].hex(),'identifier_layout_valid':n>=su_start,
      'system_use_prefix_ascii':rec[su_start:min(n,su_start+48)].decode('ascii','replace')}

def dir_data(rec):
    lba=rec['extent']['le']; n=rec['data_length']['le']; xar=rec['xar_length']
    start=lba*BLOCK+xar*BLOCK
    end=start+n
    if start<0 or end>len(raw): raise ValueError(f'extent outside image: {start}:{end}')
    return raw[start:end],start

def parse_path_table(lba,size,endian):
    start=lba*BLOCK; table=raw[start:start+size]; rows=[]; off=0
    while off<size:
        if off+8>size: return rows,{'offset':off,'reason':'truncated path table header'}
        namelen=table[off]; xar=table[off+1]; extent=int.from_bytes(table[off+2:off+6],endian); parent=int.from_bytes(table[off+6:off+8],endian)
        pad=1 if namelen%2 else 0; end=off+8+namelen+pad
        if end>size: return rows,{'offset':off,'reason':'truncated path table name'}
        name=table[off+8:off+8+namelen]
        padding=table[off+8+namelen:end]
        rows.append({'index':len(rows)+1,'offset':off,'name_hex':name.hex(),'name':'.' if name==b'\0' else name.decode('ascii','replace'),'xar_length':xar,'extent_lba':extent,'parent_directory_number':parent,'padding_hex':padding.hex()})
        off=end
    return rows,None

# Volume descriptor walk; only type 1 PVD supplies the primary namespace.
volume_descriptors=[]; pvd=None
for sector in range(16,len(raw)//BLOCK):
    desc=raw[sector*BLOCK:(sector+1)*BLOCK]
    if len(desc)<BLOCK or desc[1:6]!=b'CD001': break
    typ=desc[0]
    volume_descriptors.append({'sector':sector,'type':typ,'version':desc[6],'identifier':desc[40:72].decode('ascii','replace').rstrip()})
    if typ==1: pvd=desc
    if typ==255: break
if pvd is None: raise RuntimeError('Primary Volume Descriptor missing')
root=parse_record(pvd[156:156+pvd[156]],16*BLOCK+156)
logical=both16(pvd,128)
volume={'iso_sha256':hashlib.sha256(raw).hexdigest(),'iso_size':len(raw),'sector_size':BLOCK,
 'volume_space_size':both32(pvd,80),'volume_set_size':both16(pvd,120),'volume_sequence':both16(pvd,124),
 'logical_block_size':logical,'path_table_size':both32(pvd,132),'l_path_table_location':int.from_bytes(pvd[140:144],'little'),
 'optional_l_path_table_location':int.from_bytes(pvd[144:148],'little'),'m_path_table_location':int.from_bytes(pvd[148:152],'big'),
 'optional_m_path_table_location':int.from_bytes(pvd[152:156],'big'),'root_record':root,'descriptors':volume_descriptors}
pt_size=volume['path_table_size']['le']
path_tables={'L':parse_path_table(volume['l_path_table_location'],pt_size,'little'),
             'M':parse_path_table(volume['m_path_table_location'],pt_size,'big')}

all_dirs=[]; all_records=[]; occurrences=[]; anomalies=[]; visited=set(); name_checks=[]
def walk(path, rec, parent_extent):
    lba=rec['extent']['le']; key=(lba,rec['data_length']['le'])
    if key in visited:
        anomalies.append({'kind':'directory_extent_revisited_or_cycle','path':path,'extent':key}); return
    visited.add(key)
    payload,abs_start=dir_data(rec); dsize=len(payload)
    d={'path':path,'extent_lba':lba,'xar_length':rec['xar_length'],'data_length':dsize,'absolute_data_offset':abs_start,'records':[],'sector_zero_tails':[],'directory_slack':None}
    all_dirs.append(d)
    off=0; child_dirs=[]
    while off<dsize:
        sector_start=(off//BLOCK)*BLOCK; sector_end=min(sector_start+BLOCK,dsize)
        if payload[off]==0:
            tail=payload[off:sector_end]
            nonzero=[i for i,v in enumerate(tail) if v]
            d['sector_zero_tails'].append({'directory_offset':off,'absolute_offset':abs_start+off,'length_to_sector_end':len(tail),'all_zero':not nonzero,'nonzero_offsets_relative_to_tail':nonzero[:32],'nonzero_hex_prefix':tail[:64].hex()})
            if nonzero: anomalies.append({'kind':'nonzero_after_zero_directory_terminator','path':path,'directory_offset':off,'absolute_offset':abs_start+off,'count':len(nonzero)})
            off=sector_end; continue
        remain=sector_end-off
        reclen=payload[off]
        if reclen<34 or reclen>remain or off+reclen>dsize:
            anomalies.append({'kind':'invalid_or_sector_crossing_directory_record','path':path,'directory_offset':off,'absolute_offset':abs_start+off,'length':reclen,'sector_remaining':remain})
            # Preserve exact remaining bytes and resume at next logical sector.
            d.setdefault('unparsed_spans',[]).append({'offset':off,'length':remain,'hex':payload[off:sector_end].hex()})
            off=sector_end; continue
        r=parse_record(payload[off:off+reclen],abs_start+off)
        r['directory_path']=path; r['directory_offset']=off
        d['records'].append(r); all_records.append(r)
        if r['padding_length'] and any(bytes.fromhex(r['padding_hex'])):
            anomalies.append({'kind':'nonzero_identifier_padding','path':path,'absolute_offset':r['absolute_offset']+33+r['file_identifier_length'],'hex':r['padding_hex']})
        for field in ('extent','data_length','volume_sequence'):
            if r[field]['le']!=r[field]['be']:
                anomalies.append({'kind':'both_endian_field_mismatch','path':path,'absolute_offset':r['absolute_offset'],'field':field,'values':r[field]})
        if not r['identifier_layout_valid']:
            anomalies.append({'kind':'record_too_short_for_identifier_padding','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset'],'record_length':r['record_length'],'identifier_length':r['file_identifier_length'],'required_minimum':33+r['file_identifier_length']+r['padding_length']})
        if not r['recording_date_valid']:
            anomalies.append({'kind':'invalid_recording_date','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset'],'date':r['recording_date_parts']})
        if r['volume_sequence']['le']!=1:
            anomalies.append({'kind':'nonprimary_volume_sequence','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset'],'volume_sequence':r['volume_sequence']['le']})
        if r['file_unit_size'] or r['interleave_gap_size']:
            anomalies.append({'kind':'interleaving_present','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset'],'file_unit_size':r['file_unit_size'],'interleave_gap_size':r['interleave_gap_size']})
        if r['flags'] & 0x60:
            anomalies.append({'kind':'reserved_flag_bits_set','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset'],'flags':r['flags'],'reserved_bits':r['flags']&0x60})
        if r['xar_length']:
            occurrences.append({'path':path.rstrip('/')+'/'+r['identifier'],'record':r,'kind':'xar'})
        if r['identifier'] not in ('.','..'):
            occurrences.append({'path':path.rstrip('/')+'/'+r['identifier'],'record':r,'kind':'entry'})
        if r['flag_bits']['multi_extent']:
            anomalies.append({'kind':'multi_extent_flag','path':path,'identifier':r['identifier'],'absolute_offset':r['absolute_offset']})
        if r['system_use_length']:
            su=bytes.fromhex(r['system_use_hex']); pos=0; tags=[]; valid=True
            while pos<len(su):
                if len(su)-pos<4: valid=False; break
                sig=su[pos:pos+2].decode('ascii','replace'); ln=su[pos+2]
                if ln<4 or pos+ln>len(su): valid=False; break
                tags.append({'signature':sig,'length':ln,'version':su[pos+3]}); pos+=ln
            r['system_use_parsed_as_susp']=valid and pos==len(su)
            r['system_use_entries']=tags if r['system_use_parsed_as_susp'] else []
        ident=r['identifier']
        if r['flag_bits']['directory'] and ident not in ('.','..'):
            child_dirs.append((ident,r))
        off+=reclen
    # Directory's last sector unused bytes after declared data length.
    alloc_end=lba*BLOCK+math.ceil((rec['xar_length']*BLOCK+dsize)/BLOCK)*BLOCK
    content_abs=abs_start+dsize
    trailing=max(0,alloc_end-content_abs)
    slack=raw[content_abs:content_abs+trailing]
    d['directory_slack']={'absolute_offset':content_abs,'length':len(slack),'all_zero':not any(slack),'hex_prefix':slack[:64].hex()}
    if any(slack): anomalies.append({'kind':'nonzero_directory_sector_slack','path':path,'absolute_offset':content_abs,'length':len(slack),'hex_prefix':slack[:64].hex()})
    # Exactly one self and parent entry; compare both extent and byte length.
    dots=[x for x in d['records'] if x['identifier']=='.']; dotdots=[x for x in d['records'] if x['identifier']=='..']
    for nm,items,expected in [('.',dots,(rec['extent']['le'],rec['data_length']['le'])),('..',dotdots,parent_extent if parent_extent else (rec['extent']['le'],rec['data_length']['le']))]:
        if len(items)!=1:
            anomalies.append({'kind':'directory_special_entry_count','path':path,'identifier':nm,'count':len(items)})
        elif (items[0]['extent']['le'],items[0]['data_length']['le'])!=expected:
            anomalies.append({'kind':'directory_self_parent_mismatch','path':path,'identifier':nm,'actual':[items[0]['extent']['le'],items[0]['data_length']['le']],'expected':list(expected)})
    # Names duplicate or normalize to same ISO name; . and .. are expected aliases.
    names={}; exact_names={}
    for r in d['records']:
        if r['identifier'] in ('.','..'): continue
        exact_names.setdefault(r['identifier'],[]).append(r['identifier'])
        norm=r['identifier'].upper().split(';')[0].rstrip('.')
        names.setdefault(norm,[]).append(r['identifier'])
    name_checks.append({'path':path,'ordinary_dot_aliases':[r['identifier'] for r in d['records'] if r['identifier'] in ('.','..')],
      'exact_duplicate_names':{k:v for k,v in exact_names.items() if len(v)>1},
      'normalized_duplicate_names':{k:v for k,v in names.items() if len(v)>1},
      'normalization_policy':'ASCII uppercase, remove ISO ;version suffix, strip trailing period'})
    for norm,vals in names.items():
        if len(vals)>1:
            anomalies.append({'kind':'duplicate_normalized_name','path':path,'normalized_name':norm,'names':vals})
    for ident,child in child_dirs:
        child_extent=(child['extent']['le'],child['data_length']['le'])
        walk(path.rstrip('/')+'/'+ident,child,(lba,rec['data_length']['le']))

walk('/',root,None)

# Cross-check both-endian path tables against the reachable directory tree.
path_anomalies=[]
for label,(rows,error) in path_tables.items():
    if error: path_anomalies.append({'kind':'path_table_parse_error','table':label,**error})
    for row in rows:
        if row['padding_hex'] and any(bytes.fromhex(row['padding_hex'])):
            path_anomalies.append({'kind':'nonzero_path_table_padding','table':label,'entry':row['index'],'hex':row['padding_hex']})
Lrows,Lerr=path_tables['L']; Mrows,Merr=path_tables['M']
if not Lerr and not Merr:
    norm=lambda rs:[(r['name_hex'],r['xar_length'],r['extent_lba'],r['parent_directory_number']) for r in rs]
    if norm(Lrows)!=norm(Mrows): path_anomalies.append({'kind':'little_big_path_table_mismatch'})
    if not Lrows or (Lrows[0]['name_hex'],Lrows[0]['extent_lba'],Lrows[0]['parent_directory_number'])!=('00',root['extent']['le'],1):
        path_anomalies.append({'kind':'path_table_root_mismatch','actual':Lrows[0] if Lrows else None,'expected':{'name_hex':'00','extent_lba':root['extent']['le'],'parent_directory_number':1}})
    expected=[]
    ordered_paths=sorted((d['path'] for d in all_dirs),key=lambda p:(p.count('/'),p.encode('ascii')))
    path_to_index={p:i+1 for i,p in enumerate(ordered_paths)}
    for d in all_dirs:
        if d['path']=='/': continue
        parent=d['path'].rsplit('/',1)[0] or '/'
        expected.append({'path':d['path'],'name':d['path'].rsplit('/',1)[1].encode('ascii').hex(),'extent_lba':d['extent_lba'],'parent_directory_number':path_to_index[parent]})
    actual={r['name_hex']:r for r in Lrows[1:]}
    for e in expected:
        r=actual.get(e['name'])
        if not r or any(r[k]!=e[k] for k in ('extent_lba','parent_directory_number')):
            path_anomalies.append({'kind':'path_table_directory_mismatch','expected':e,'actual':r})
    if len(Lrows)!=len(all_dirs): path_anomalies.append({'kind':'path_table_directory_count_mismatch','path_table_count':len(Lrows),'directory_count':len(all_dirs)})
anomalies.extend(path_anomalies)

# Sector allocation overlaps among named extents. This includes XAR blocks before file data.
allocated=[]
file_slack=[]
# Include the PVD's root directory extent in allocation overlap checks.
root_blocks=math.ceil((root['xar_length']*BLOCK+root['data_length']['le'])/BLOCK)
allocated.append({'path':'/','kind':'directory','start_lba':root['extent']['le'],'end_lba_exclusive':root['extent']['le']+root_blocks,'xar_length':root['xar_length'],'data_length':root['data_length']['le'],'file_unit_size':root['file_unit_size'],'interleave_gap_size':root['interleave_gap_size']})
for vd in volume_descriptors:
    allocated.append({'path':f"<volume-descriptor-sector-{vd['sector']}>",'kind':'volume_descriptor','start_lba':vd['sector'],'end_lba_exclusive':vd['sector']+1,'xar_length':0,'data_length':BLOCK,'file_unit_size':0,'interleave_gap_size':0})
for label,lba in (('L',volume['l_path_table_location']),('M',volume['m_path_table_location'])):
    n=volume['path_table_size']['le']; blocks=math.ceil(n/BLOCK)
    allocated.append({'path':f'<{label}-path-table>','kind':'path_table','start_lba':lba,'end_lba_exclusive':lba+blocks,'xar_length':0,'data_length':n,'file_unit_size':0,'interleave_gap_size':0})
for e in occurrences:
    r=e['record']; n=r['data_length']['le']; start=r['extent']['le']; blocks=math.ceil((r['xar_length']*BLOCK+n)/BLOCK)
    if not blocks: continue
    allocated.append({'path':e['path'],'kind':'directory' if r['flag_bits']['directory'] else 'file','start_lba':start,'end_lba_exclusive':start+blocks,'xar_length':r['xar_length'],'data_length':n,'file_unit_size':r['file_unit_size'],'interleave_gap_size':r['interleave_gap_size']})
    if not r['flag_bits']['directory'] and not r['file_unit_size'] and not r['interleave_gap_size']:
        content_start=start*BLOCK+r['xar_length']*BLOCK
        content_end=content_start+n
        alloc_end=(start+blocks)*BLOCK
        slack=raw[content_end:alloc_end]
        item={'path':e['path'],'absolute_offset':content_end,'length':len(slack),'all_zero':not any(slack),'sha256':hashlib.sha256(slack).hexdigest() if slack else hashlib.sha256(b'').hexdigest(),'hex':slack.hex()}
        file_slack.append(item)
        if any(slack): anomalies.append({'kind':'nonzero_file_sector_slack','path':e['path'],'absolute_offset':content_end,'length':len(slack),'hex_prefix':slack[:64].hex()})
collisions=[]
for i,a in enumerate(allocated):
    for b in allocated[i+1:]:
        lo=max(a['start_lba'],b['start_lba']); hi=min(a['end_lba_exclusive'],b['end_lba_exclusive'])
        if lo<hi: collisions.append({'a':a['path'],'b':b['path'],'overlap_lba':[lo,hi]})

summary={'scope':'Raw ISO 9660 primary directory record parsing; image read only, never mounted or executed.','volume':volume,
 'directory_count':len(all_dirs),'record_count':len(all_records),'directory_records':[{'path':d['path'],'extent_lba':d['extent_lba'],'xar_length':d['xar_length'],'data_length':d['data_length'],'absolute_data_offset':d['absolute_data_offset'],'records':d['records'],'sector_zero_tails':d['sector_zero_tails'],'directory_slack':d['directory_slack'],'unparsed_spans':d.get('unparsed_spans',[])} for d in all_dirs],
 'path_tables':{'L':{'lba':volume['l_path_table_location'],'entries':Lrows,'parse_error':Lerr},'M':{'lba':volume['m_path_table_location'],'entries':Mrows,'parse_error':Merr},'cross_checks':path_anomalies},
 'allocation_extents':allocated,'file_sector_slack':file_slack,'name_checks':name_checks,'extent_collisions':collisions,'anomalies':anomalies,
 'summary_counts':{'sector_zero_tails':sum(len(d['sector_zero_tails']) for d in all_dirs),'nonzero_zero_tails':sum(not t['all_zero'] for d in all_dirs for t in d['sector_zero_tails']),'system_use_records':sum(bool(r['system_use_length']) for r in all_records),'records_with_padding':sum(r['padding_length']>0 for r in all_records),'nonzero_padding_records':sum(bool(r['padding_hex'] and any(bytes.fromhex(r['padding_hex']))) for r in all_records),'xar_records':sum(r['xar_length']>0 for r in all_records),'interleaved_records':sum(bool(r['file_unit_size'] or r['interleave_gap_size']) for r in all_records),'multi_extent_records':sum(r['flag_bits']['multi_extent'] for r in all_records),'reserved_flag_records':sum(bool(r['flags']&0x60) for r in all_records),'file_slack_nonzero':sum(not x['all_zero'] for x in file_slack),'extent_collisions':len(collisions),'flag_histogram':{hex(v):sum(r['flags']==v for r in all_records) for v in sorted(set(r['flags'] for r in all_records))},'invalid_recording_dates':sum(not r['recording_date_valid'] for r in all_records),'nonprimary_volume_sequences':sum(r['volume_sequence']['le']!=1 for r in all_records),'anomalies':len(anomalies)}}
(OUT/'directory-record-audit.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print(json.dumps(summary['summary_counts'],indent=2))
