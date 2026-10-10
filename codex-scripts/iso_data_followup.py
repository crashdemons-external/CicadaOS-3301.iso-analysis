from pathlib import Path
import hashlib, json, math, re

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/iso-audit'
ISO=OUT/'iso-files'

# Full-stream descriptive statistics.
def stats(p):
    b=p.read_bytes(); n=len(b); counts=[0]*256
    for x in b: counts[x]+=1
    entropy=-sum((c/n)*math.log2(c/n) for c in counts if c)
    expected=n/256
    chi=sum((c-expected)**2/expected for c in counts)
    return {'path':str(p.relative_to(ROOT)),'size':n,'sha256':hashlib.sha256(b).hexdigest(),'histogram':[{'byte':i,'count':c} for i,c in enumerate(counts)],'distinct_values':sum(c>0 for c in counts),'entropy_bits_per_byte':entropy,'chi_square_uniform_256_bins':chi,'df':255}

def factors(n):
    orig=n; out=[]; d=2
    while d*d<=n:
        e=0
        while n%d==0: n//=d; e+=1
        if e: out.append([d,e])
        d=3 if d==2 else d+2
    if n>1: out.append([n,1])
    return {'value':orig,'prime':len(out)==1 and out[0][1]==1,'factors':out}

def match(container, needle):
    return container.find(needle)

folly=(OUT/'rootfs/tmp/folly').read_bytes(); wisdom=(OUT/'rootfs/tmp/wisdom').read_bytes()
containers={'560.13':(ISO/'DATA/560.13').read_bytes(),'560.17':(ISO/'DATA/560.17').read_bytes(),'_560.00':(ISO/'DATA/_560.00').read_bytes(),'761.MP3':(ISO/'AUDIO/761.MP3').read_bytes()}
substring=[]
folly_candidates=[('folly_full',folly),('wisdom_full',wisdom),('folly_reverse_full',folly[::-1])]
for n in (64,256,1024):
    folly_candidates.extend([(f'folly_prefix_{n}',folly[:n]),(f'folly_reverse_prefix_{n}',folly[::-1][:n])])
for n,data in containers.items():
    for label,needle in folly_candidates:
        substring.append({'candidate':label,'container':n,'needle_size':len(needle),'offset':match(data,needle)})

# Check whether the first 64 bytes of each extracted DATA stream occur anywhere
# in each other DATA stream, and record direct 64-byte prefix equality.
data_streams={name:containers[name] for name in ('560.13','560.17','_560.00')}
data_pairwise=[]
for left_name,left in data_streams.items():
    for right_name,right in data_streams.items():
        if left_name==right_name: continue
        data_pairwise.append({'needle_file':left_name,'needle':'first_64_bytes','container_file':right_name,'prefix_equal':left[:64]==right[:64],'occurrence_offset':right.find(left[:64])})

# Same-directory .rev comparisons avoid cross-corpus and Git LFS pointer artifacts.
rev=[]
for rp in sorted((ROOT/'archives').rglob('*.rev')):
    base=rp.with_name(rp.name[:-4])
    if not base.is_file(): continue
    rb=rp.read_bytes(); ob=base.read_bytes()
    rev.append({'rev':str(rp.relative_to(ROOT)),'original':str(base.relative_to(ROOT)),'sizes':[len(rb),len(ob)],'identical':rb==ob,'literal_reverse':len(rb)==len(ob) and rb==ob[::-1],'rev_sha256':hashlib.sha256(rb).hexdigest(),'original_sha256':hashlib.sha256(ob).hexdigest()})

# Rebuild tweet payload directly from its archived offset:hex listing using the documented seek/write semantics.
tw=ROOT/'archives/neuroretransmit-cicada/2013/003-twitter'
records=[]
for line in (tw/'tweets/full.txt').read_text(encoding='ascii').splitlines():
    m=re.fullmatch(r'([0-9a-fA-F]+):\s*([0-9a-fA-F]+)',line.strip())
    if m: records.append((int(m.group(1),16),bytes.fromhex(m.group(2))))
size=max((off+len(blob) for off,blob in records),default=0)
rebuilt=bytearray(size)
for off,blob in records: rebuilt[off:off+len(blob)]=blob
rebuilt_path=OUT/'twitter-rebuilt.bin'; rebuilt_path.write_bytes(rebuilt)
saved=(tw/'twitter.bin').read_bytes()
# Calculate disagreements over common logical length and reconstructed file final extent.
diff_count=sum(a!=b for a,b in zip(rebuilt,saved))

# Direct identified byte histogram and file-length factorization.
files=[OUT/'rootfs/tmp/folly',OUT/'rootfs/tmp/wisdom',ISO/'DATA/560.13',ISO/'DATA/560.17',ISO/'DATA/_560.00',ISO/'AUDIO/761.MP3']
summary={
 'scope':'Static stream statistics and matching only; no code executed.',
 'folly_wisdom':{'identical':folly==wisdom,'folly_stats':stats(OUT/'rootfs/tmp/folly'),'wisdom_stats':stats(OUT/'rootfs/tmp/wisdom'),'same_prefix_as_each_other':{str(n):folly[:n]==wisdom[:n] for n in (64,256,1024,3368)}},
 'data_stream_stats':[stats(p) for p in files[2:]],
 'length_factorizations':[factors(p.stat().st_size) for p in files],
 'substring_searches':substring,
 'pairwise_data_prefix_searches':data_pairwise,
 'same_directory_rev_pairs':rev,
 'twitter_reconstruction':{'records_parsed':len(records),'max_extent':size,'saved_size':len(saved),'rebuilt_sha256':hashlib.sha256(rebuilt).hexdigest(),'saved_sha256':hashlib.sha256(saved).hexdigest(),'byte_identical':rebuilt==saved,'common_extent_disagreements':diff_count,'records_without_parse':len((tw/'tweets/full.txt').read_text(encoding='ascii').splitlines())-len(records),'output':str(rebuilt_path.relative_to(ROOT))}
}
(OUT/'data-followup.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print('records',len(records),'extent',size,'saved',len(saved),'identical',rebuilt==saved,'diff',diff_count,'rev pairs',len(rev),'reverse hits',sum(x['literal_reverse'] for x in rev))
