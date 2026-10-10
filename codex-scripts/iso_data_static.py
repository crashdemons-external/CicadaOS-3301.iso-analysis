from pathlib import Path
import hashlib, json

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/iso-audit'
ISO = OUT / 'iso-files'
ARCHIVES = ROOT / 'archives'

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def identical(a,b): return a.read_bytes() == b.read_bytes()
def describe(p):
    b=p.read_bytes()
    return {'path': str(p.relative_to(ROOT)), 'size':len(b), 'sha256':hashlib.sha256(b).hexdigest()}

# Locate documented source/copies and .rev variants by filename, without executing them.
names = ['_560.00','560.13','560.17','761.MP3','folly','wisdom']
paths=[]
for p in [*ISO.rglob('*'), *ARCHIVES.rglob('*')]:
    if p.is_file() and (p.name in names or p.name.endswith('.rev') and any(n in p.name for n in names)):
        paths.append(p)

comparisons=[]
for name in names:
    group=[p for p in paths if p.name.lower()==name.lower()]
    if name.lower()=='761.mp3': group=[p for p in paths if p.name.lower()=='761.mp3']
    if name in ('folly','wisdom'):
        group += [OUT/'rootfs'/'tmp'/name]
    group=[p for p in dict.fromkeys(group) if p.exists()]
    comparisons.append({'name':name, 'copies':[describe(p) for p in group], 'all_byte_identical': all(identical(group[0],p) for p in group[1:]) if group else None})

# Verify historical 2013 Twitter XOR intermediates against exact extracted and archived inputs.
tw=ARCHIVES/'neuroretransmit-cicada/2013/003-twitter'
source=ARCHIVES/'neuroretransmit-cicada/2013/002-3301/3301-contents'
iso_data=ISO/'DATA'
iso_audio=ISO/'AUDIO'/'761.MP3'
iso560=iso_data/'560.13'
archive_audio=source/'audio'/'761.mp3'
archive560=ARCHIVES/'archive3/assets/2013/cicados/DATA/560.13'
def xor_bytes(a,b):
    x,y=a.read_bytes(),b.read_bytes()
    z=bytes(i^j for i,j in zip(x,y))
    return {'input_lengths':[len(x),len(y)],'xor_output_length':len(z),'truncated_to_shorter_input':len(x)!=len(y),'xor_sha256':hashlib.sha256(z).hexdigest()}
intermediate=tw/'560.13^761.mp3.bin'
checks={
 'iso_data_56013_vs_archive': {'byte_identical':identical(iso560,archive560),'iso':describe(iso560),'archive':describe(archive560)},
 'iso_audio_vs_archive': {'byte_identical':identical(iso_audio,archive_audio),'iso':describe(iso_audio),'archive':describe(archive_audio)},
 'iso_56013_xor_iso_761_vs_saved_intermediate': {'computed':xor_bytes(iso560,iso_audio),'saved':describe(intermediate),'byte_identical': (iso560.read_bytes()[:len(iso_audio.read_bytes())] and bytes(a^b for a,b in zip(iso560.read_bytes()[:len(iso_audio.read_bytes())],iso_audio.read_bytes())) == intermediate.read_bytes())},
}
# Verify the next documented stage: saved Twitter bytes XOR audio yields the documented JPEG.
twitter=tw/'twitter.bin'; gematria=tw/'gematria.jpg'
checks['twitter_xor_audio_vs_gematria']={'computed':xor_bytes(twitter,iso_audio),'saved':describe(gematria),'byte_identical':bytes(a^b for a,b in zip(twitter.read_bytes(),iso_audio.read_bytes()))==gematria.read_bytes()}
# Reproduce 2013 first-onion clue XOR and one third-onion offset message from documented streams.
clue=ARCHIVES/'neuroretransmit-cicada/2013/004-first-onion/clue.txt.bin'
clue_xor=bytes(a^b for a,b in zip(clue.read_bytes(),(iso_data/'_560.00').read_bytes()))
clue_out=OUT/'clue-xor.bin'; clue_out.write_bytes(clue_xor)
checks['first_onion_clue_xor']={'inputs':[describe(clue),describe(iso_data/'_560.00')],'output':describe(clue_out),'matches_archived_asc_after_newline_normalization':clue_xor==(ARCHIVES/'neuroretransmit-cicada/2013/004-first-onion/clue.txt.asc').read_bytes().replace(bytes([13,10]),bytes([10]))}
phone_hex=bytes.fromhex('28C07E1B102D4D5C4C1A376E064477E1416FCC94928765')
phone_offset=12821; stream=iso560.read_bytes()
phone_plain=bytes(a^b for a,b in zip(stream[phone_offset:phone_offset+len(phone_hex)],phone_hex))
phone_out=OUT/'third-onion-offset-12821.bin'; phone_out.write_bytes(phone_plain)
checks['third_onion_offset_12821']={'offset':phone_offset,'ciphertext_hex':phone_hex.hex(),'plaintext_hex':phone_plain.hex(),'plaintext_ascii':phone_plain.decode('ascii','replace'),'saved':describe(phone_out)}
# Relationship check: equal folly/wisdom byte streams, lengths, entropy indicators, and byte distribution.
f=OUT/'rootfs/tmp/folly'; w=OUT/'rootfs/tmp/wisdom'
fb,wb=f.read_bytes(),w.read_bytes()
checks['folly_wisdom']={'identical':fb==wb,'lengths':[len(fb),len(wb)],'sha256':[sha(f),sha(w)],'distinct_byte_values':len(set(fb)),'zero_bytes':fb.count(0),'printable_ascii_bytes':sum(32<=c<127 for c in fb),'first_64_hex':fb[:64].hex()}
# Determine whether archived .rev assets are literal byte reversals of corresponding files.
rev_relationships=[]
for rp in [p for p in paths if p.name.endswith('.rev')]:
    base=rp.with_name(rp.name[:-4])
    candidates=[p for p in paths if p.name.lower()==base.name.lower() and not p.name.endswith('.rev')]
    for cp in candidates:
        rb,cb=rp.read_bytes(),cp.read_bytes()
        rev_relationships.append({'rev':str(rp.relative_to(ROOT)),'candidate':str(cp.relative_to(ROOT)),'sizes':[len(rb),len(cb)],'literal_reverse':len(rb)==len(cb) and rb==cb[::-1], 'identical':rb==cb})
(OUT/'data-static.json').write_text(json.dumps({'scope':'Static byte-level comparison of already extracted ISO files and archived 2013 artifacts. No code executed.','comparisons':comparisons,'checks':checks,'rev_relationships':rev_relationships},indent=2)+'\n',encoding='utf-8')
print('Wrote output/iso-audit/data-static.json')







