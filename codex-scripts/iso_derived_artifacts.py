"""Reproduce known XOR images as data and audit derived PNG chunks."""
from pathlib import Path
import base64, hashlib, json, struct, zlib
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'output/iso-audit'
audio=(OUT/'iso-files/AUDIO/761.MP3').read_bytes()
dataset=(OUT/'iso-files/DATA/560.13').read_bytes()
twitter=(OUT/'twitter-rebuilt.bin').read_bytes()
jpg=bytes(x^y for x,y in zip(twitter,audio))
assert jpg==(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/gematria.jpg').read_bytes()
(OUT/'gematria-reproduced.jpg').write_bytes(jpg)
triple=bytes(x^y^z for x,y,z in zip(twitter,audio,dataset))
(OUT/'twitter-audio-data13-xor.txt').write_bytes(triple)
delimiter=triple.find(b'-'*65)
assert delimiter>=0
b64=triple[:delimiter].strip()
decoded=base64.b64decode(b64)
assert decoded==(ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/decoded.png').read_bytes()
(OUT/'cicada-reproduced.png').write_bytes(decoded)
assert decoded[:8]==b'\x89PNG\r\n\x1a\n'
pos=8;chunks=[]
while pos+12<=len(decoded):
    size=int.from_bytes(decoded[pos:pos+4],'big');typ=decoded[pos+4:pos+8]
    end=pos+12+size
    assert end<=len(decoded)
    payload=decoded[pos+8:pos+8+size]
    crc=int.from_bytes(decoded[pos+8+size:end],'big')
    chunks.append({'offset':pos,'type':typ.decode(),'size':size,'crc_valid':crc==zlib.crc32(typ+payload)})
    pos=end
    if typ==b'IEND':break
result={'gematria':{'size':len(jpg),'sha256':hashlib.sha256(jpg).hexdigest(),'exact_archived_match':True},
    'triple_xor':{'size':len(triple),'base64_before_delimiter_size':len(b64),'delimiter_offset':delimiter,
                  'tail_pattern_values':sorted(set(triple[delimiter+65:].strip()))},
    'png':{'size':len(decoded),'sha256':hashlib.sha256(decoded).hexdigest(),'exact_archived_match':True,
           'chunks':chunks,'bytes_after_iend':len(decoded)-pos},
    'caveat':'Reproduction of documented historical artifacts, not a newly solved puzzle. No OutGuess extractor was run; archived OutGuess content was reviewed as secondary derived evidence.'}
(OUT/'derived-artifacts.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
