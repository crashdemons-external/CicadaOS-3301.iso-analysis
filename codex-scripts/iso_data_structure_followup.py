from pathlib import Path
import base64, bz2, hashlib, json, struct, zlib

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/iso-audit'
ISO=OUT/'iso-files'
DATA=ISO/'DATA'
D=(DATA/'560.13').read_bytes(); A=(ISO/'AUDIO'/'761.MP3').read_bytes()
T=(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/twitter.bin').read_bytes()
S=bytes(x^y for x,y in zip(D,A))
Q=bytes(x^y for x,y in zip(S,T))
(OUT/'data13-audio-twitter-prefix.bin').write_bytes(Q)
(OUT/'data13-audio-xor.bin').write_bytes(S)

# The archived b64 text uses CRLF line endings; the computed XOR stream has LF only.
arch_b64=(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/b64.txt').read_bytes()
b64_equal=arch_b64.replace(bytes([13]),b'')==Q
sep=Q.find(b'-'*65)
line_start=Q.rfind(bytes([10]),0,sep)+1
line_end=Q.find(bytes([10]),sep)
if sep<0 or line_end<0: raise RuntimeError('Expected 65-hyphen separator line was not found')
base64_region=Q[:line_start].replace(bytes([10]),b'')
png=base64.b64decode(base64_region,validate=True)
archive_png=(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/decoded.png').read_bytes()
(OUT/'data13-twitter-base64-decoded.png').write_bytes(png)
pattern=Q[line_end+1:]
pattern_logical=pattern.replace(bytes([10]),b'')
pattern_file=(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/only_pattern.txt').read_bytes().replace(bytes([13]),b'').replace(bytes([10]),b'')
# Match the periodic motif from its observed beginning and test every candidate phase for S beyond T.
motif=b'33010'
run=0
for i,b in enumerate(pattern_logical):
    if b!=motif[i%len(motif)]: break
    run+=1
phase_checks=[]
for phase in range(len(motif)):
    n=0
    for i,b in enumerate(S[len(T):]):
        if b!=motif[(phase+i)%len(motif)]: break
        n+=1
    phase_checks.append({'phase':phase,'consecutive_match_bytes':n,'first_deviation_absolute_offset':len(T)+n if n<len(S)-len(T) else None,'observed_at_start_hex':S[len(T):len(T)+16].hex()})

# File-format signature scan on the three DATA streams. Signatures nominate locations only.
sigs={
 'png':bytes.fromhex('89504e470d0a1a0a'),'gzip':bytes.fromhex('1f8b08'),
 'zip':bytes.fromhex('504b0304'),'pdf':b'%PDF-','elf':bytes.fromhex('7f454c46'),
 'bzip2':b'BZh','xz':bytes.fromhex('fd377a585a00'),'sqlite':b'SQLite format 3\0',
 '7z':bytes.fromhex('377abcaf271c'),'rar':bytes.fromhex('526172211a0700'),
 'gif87a':b'GIF87a','gif89a':b'GIF89a','riff_webp':b'RIFF'
}
def offsets_all(buf,needle,limit=200):
    result=[]; start=0
    while len(result)<limit:
        k=buf.find(needle,start)
        if k<0: break
        result.append(k); start=k+1
    return result

def validate_png(buf,off):
    p=off+8; chunks=[]
    while p+12<=len(buf) and len(chunks)<10000:
        n=struct.unpack('>I',buf[p:p+4])[0]
        if n>len(buf)-p-12: return {'valid':False,'reason':'truncated_or_oversized_chunk','chunks':chunks}
        typ=buf[p+4:p+8]; payload=buf[p+8:p+8+n]; crc=struct.unpack('>I',buf[p+8+n:p+12+n])[0]
        if zlib.crc32(typ+payload)&0xffffffff != crc: return {'valid':False,'reason':'crc_mismatch','chunks':chunks}
        chunks.append(typ.decode('ascii','replace')); p+=12+n
        if typ==b'IEND': return {'valid':True,'length':p-off,'chunks':chunks}
    return {'valid':False,'reason':'missing_iend_or_limit','chunks':chunks}

def validate_comp(buf,off,wbits,max_output=8*1024*1024):
    d=zlib.decompressobj(wbits); pos=off; total=0
    try:
        while pos<len(buf) and total<max_output:
            chunk=buf[pos:pos+65536]; pos+=len(chunk)
            out=d.decompress(chunk,max_output-total); total+=len(out)
            while d.unconsumed_tail and total<max_output:
                out=d.decompress(d.unconsumed_tail,max_output-total); total+=len(out)
            if d.eof: return {'valid':True,'compressed_length':pos-off-len(d.unused_data),'decompressed_bytes':total}
        return {'valid':False,'reason':'not_eof_within_input_or_8MiB_output_cap','decompressed_bytes':total}
    except zlib.error as e: return {'valid':False,'reason':str(e)[:160]}

def validate_bzip2(buf, off, max_output=8*1024*1024):
    if buf[off+3:off+4] not in tuple(bytes([x]) for x in range(49,58)):
        return {'valid':False,'reason':'invalid_block_size_byte'}
    d=bz2.BZ2Decompressor(); pos=off; total=0
    try:
        while total<max_output:
            if d.needs_input:
                if pos>=len(buf): break
                chunk=buf[pos:pos+65536]; pos+=len(chunk)
            else: chunk=b''
            total+=len(d.decompress(chunk,max_length=max_output-total))
            if d.eof:
                return {'valid':True,'compressed_length':pos-off-len(d.unused_data),'decompressed_bytes':total}
        return {'valid':False,'reason':'not_eof_within_input_or_8MiB_output_cap','decompressed_bytes':total}
    except (OSError, EOFError, ValueError) as e:
        return {'valid':False,'reason':str(e)[:160]}

signature_results={}
for name in ('_560.00','560.13','560.17'):
    buf=(DATA/name).read_bytes(); found={}
    for label,signature in sigs.items():
        found[label]=offsets_all(buf,signature)
    png_valid=[{'offset':o,**validate_png(buf,o)} for o in found['png'][:64]]
    gzip_valid=[{'offset':o,**validate_comp(buf,o,31)} for o in found['gzip'][:64]]
    bzip2_valid=[{'offset':o,**validate_bzip2(buf,o)} for o in found['bzip2'][:64]]
    # Common RFC 1950 zlib CMF/FLG bytes; validate only a bounded set of candidate starts.
    zlib_candidates=[]
    for h in (bytes.fromhex(x) for x in ('7801','785e','789c','78da')):
        for o in offsets_all(buf,h,64): zlib_candidates.append(o)
    zlib_valid=[{'offset':o,**validate_comp(buf,o,15)} for o in sorted(set(zlib_candidates))[:128]]
    signature_results[name]={'file_size':len(buf),'signature_offsets':found,'png_validation':png_valid,'gzip_validation':gzip_valid,'bzip2_validation':bzip2_valid,'zlib_candidate_offsets_checked':sorted(set(zlib_candidates))[:128],'zlib_validations':zlib_valid}

# Compact summary and full file signatures are retained, not any candidate decompressed payloads.
summary={
 'scope':'Static XOR reconstruction and bounded signature validation of extracted data only; no code execution.',
 'reconstruction':{'data13_size':len(D),'audio_size':len(A),'twitter_size':len(T),'data13_xor_audio_size':len(S),'data13_xor_audio_sha256':hashlib.sha256(S).hexdigest(),'reconstructed_prefix_size':len(Q),'reconstructed_prefix_sha256':hashlib.sha256(Q).hexdigest(),'matches_archived_b64_after_removing_cr':b64_equal,'saved_prefix':'output\\iso-audit\\data13-audio-twitter-prefix.bin','saved_data13_audio_xor':'output\\iso-audit\\data13-audio-xor.bin'},
 'structured_region':{'separator_offset':sep,'separator_line_start':line_start,'separator_line_end_exclusive':line_end,'base64_encoded_bytes_without_linefeeds':len(base64_region),'base64_decoded_size':len(png),'png_matches_archived_decoded_png':png==archive_png,'png_ihdr_dimensions':list(struct.unpack('>II',png[16:24])),'pattern_start_offset':line_end+1,'pattern_region_with_linefeeds_size':len(pattern),'pattern_region_logical_size':len(pattern_logical),'pattern_matches_archived_only_pattern_without_linebreaks':pattern_logical==pattern_file,'pattern_motif':motif.decode('ascii'),'initial_periodic_bytes':run,'first_motif_deviation_offset':line_end+1+run if run<len(pattern_logical) else None,'pattern_tail_ascii':pattern_logical[-32:].decode('ascii','replace')},
 'beyond_twitter_extent':{'start_offset':len(T),'end_offset_exclusive':len(A),'available_bytes':len(S)-len(T),'phase_checks':phase_checks,'ascii_3301_count_in_tail':S[len(T):].count(b'3301'),'exact_16_byte_pattern_occurrences_in_tail':S[len(T):].count((b'3301'*4))},
 'data_file_signature_scan':signature_results
}
(OUT/'data-structure-followup.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print('prefix equality',b64_equal,'png exact',png==archive_png,'pattern exact',pattern_logical==pattern_file,'pattern bytes',len(pattern_logical),'first motif deviation',summary['structured_region']['first_motif_deviation_offset'])
print('tail phase checks',phase_checks)
for name,res in signature_results.items(): print(name,'candidate counts', {k:len(v) for k,v in res['signature_offsets'].items()},'png valid',sum(x['valid'] for x in res['png_validation']),'gzip valid',sum(x['valid'] for x in res['gzip_validation']),'zlib valid',sum(x['valid'] for x in res['zlib_validations']))
