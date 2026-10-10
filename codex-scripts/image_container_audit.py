#!/usr/bin/env python3
"""Bounded, read-only container audit for two derived 3301 ISO images."""
import hashlib, json, math, struct, zlib
from collections import Counter
from pathlib import Path
from PIL import Image
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/iso-audit'; MAX_FILE=10_000_000; MAX_PIXELS=2_000_000

def sha(b): return hashlib.sha256(b).hexdigest()
def entropy(vals):
 c=Counter(vals); n=len(vals)
 return round(-sum((x/n)*math.log2(x/n) for x in c.values()),5) if n else 0

def png_audit(path):
 b=path.read_bytes()
 if len(b)>MAX_FILE or not b.startswith(b'\x89PNG\r\n\x1a\n'): raise ValueError('bad/oversize PNG')
 pos=8; chunks=[]; idat=[]; iend_end=None; metas={}; crc_bad=[]
 while pos+12<=len(b):
  n=struct.unpack_from('>I',b,pos)[0]; typ=b[pos+4:pos+8]
  if n>MAX_FILE or pos+12+n>len(b): raise ValueError(f'chunk boundary invalid at {pos}')
  data=b[pos+8:pos+8+n]; stored=struct.unpack_from('>I',b,pos+8+n)[0]
  good=(zlib.crc32(typ+data)&0xffffffff)==stored
  chunks.append({'offset':pos,'type':typ.decode('ascii','replace'),'length':n,'crc32':f'{stored:08x}','crc_valid':good})
  if not good: crc_bad.append(typ.decode('ascii','replace'))
  if typ==b'IDAT': idat.append(data)
  if typ==b'tIME' and n==7: metas['tIME']=dict(zip(['year','month','day','hour','minute','second'],struct.unpack('>H5B',data)))
  if typ==b'pHYs' and n==9: metas['pHYs']=dict(zip(['pixels_per_unit_x','pixels_per_unit_y','unit'],struct.unpack('>IIB',data)))
  if typ==b'bKGD': metas['bKGD']={'raw_hex':data.hex(),'length':n}
  if typ==b'IHDR' and n==13:
   w,h,depth,color,comp,filt,inter=struct.unpack('>IIBBBBB',data); metas['IHDR']=dict(width=w,height=h,bit_depth=depth,color_type=color,compression=comp,filter=filt,interlace=inter)
  pos+=12+n
  if typ==b'IEND': iend_end=pos; break
 if not metas.get('IHDR'): raise ValueError('no IHDR')
 width,height=metas['IHDR']['width'],metas['IHDR']['height']
 if width*height>MAX_PIXELS: raise ValueError('pixel limit exceeded')
 comp=b''.join(idat); dec=zlib.decompressobj(); raw=dec.decompress(comp,(height*(width*8+1))+1); raw+=dec.flush()
 bpp=2 if metas['IHDR']['color_type']==4 else 4 if metas['IHDR']['color_type']==6 else 1
 stride=width*bpp; filters=[]; rows=[]; at=0; prev=bytearray(stride)
 for _ in range(height):
  if at+stride+1>len(raw): raise ValueError('short scanline data')
  ft=raw[at]; row=bytearray(raw[at+1:at+1+stride]); at+=stride+1; filters.append(ft)
  if ft==1:
   for j in range(stride): row[j]=(row[j]+(row[j-bpp] if j>=bpp else 0))&255
  elif ft==2:
   for j in range(stride): row[j]=(row[j]+prev[j])&255
  elif ft==3:
   for j in range(stride): row[j]=(row[j]+((row[j-bpp] if j>=bpp else 0)+prev[j])//2)&255
  elif ft==4:
   for j in range(stride):
    a=row[j-bpp] if j>=bpp else 0; bb=prev[j]; c=prev[j-bpp] if j>=bpp else 0; p=a+bb-c
    pa,pb,pc=abs(p-a),abs(p-bb),abs(p-c); pr=a if pa<=pb and pa<=pc else bb if pb<=pc else c
    row[j]=(row[j]+pr)&255
  elif ft!=0: raise ValueError(f'unknown filter {ft}')
  rows.append(row); prev=row
 pil=Image.open(path); pil.load(); bands=pil.getbands(); plane_stats={}
 for band in bands:
  vals=list(pil.getchannel(band).get_flattened_data()); c=Counter(vals); plane_stats[band]={'unique':len(c),'min':min(vals),'max':max(vals),'entropy_bits_per_pixel':entropy(vals),'lsb_ones':sum(v&1 for v in vals),'lsb_entropy':entropy([v&1 for v in vals])}
 z=dec.unused_data
 return {'file':str(path.relative_to(ROOT)),'size_bytes':len(b),'sha256':sha(b),'format':pil.format,'mode':pil.mode,'dimensions':[width,height], 'chunks':chunks,'all_chunk_crc_valid':not crc_bad,'bad_crc_types':crc_bad,'png_metadata':metas,'idat':{'compressed_bytes':len(comp),'sha256':sha(comp),'zlib_eof':dec.eof,'unused_data_bytes':len(z),'unused_data_hex':z[:64].hex(),'unconsumed_tail_bytes':len(dec.unconsumed_tail),'decompressed_bytes':len(raw),'expected_scanline_bytes':height*(stride+1),'extra_decompressed_bytes':len(raw)-height*(stride+1)},'row_filter_counts':dict(sorted(Counter(filters).items())),'pil_info':{k:str(v) for k,v in pil.info.items()},'planes':plane_stats,'trailing_after_iend_bytes':len(b)-(iend_end or len(b)),'trailing_hex':b[iend_end:iend_end+64].hex() if iend_end else ''}

def create_png_previews(path):
 """Create deterministic, derived display aids from the PNG grayscale plane."""
 im=Image.open(path).convert('LA'); lum=im.getchannel('L')
 vals=list(lum.get_flattened_data())
 lo,hi=min(vals),max(vals)
 # Explicit min-max contrast stretch; preserve shape, no interpolation.
 contrast=lum.point(lambda x: round((x-lo)*255/(hi-lo)) if hi>lo else 0)
 paths=[]
 p=OUT/'cicada-png-contrast-preview-audit.png'; contrast.save(p,optimize=False); paths.append(p)
 for bit in range(3):
  plane=lum.point(lambda x,b=bit: 255 if (x>>b)&1 else 0)
  p=OUT/f'cicada-png-bitplane-{bit}-audit.png'; plane.save(p,optimize=False); paths.append(p)
 return [{'file':str(p.relative_to(ROOT)),'size_bytes':p.stat().st_size,'sha256':sha(p.read_bytes())} for p in paths]

def jpeg_audit(path):
 b=path.read_bytes()
 if len(b)>MAX_FILE or not b.startswith(b'\xff\xd8'): raise ValueError('bad/oversize JPEG')
 pos=2; segments=[]; scans=0; eoi=None; bad=[]; in_entropy=False
 while pos<len(b):
  if in_entropy:
   # skip entropy-coded bytes, stuffed FF00, and restart markers; stop at next real marker
   while pos<len(b):
    q=b.find(b'\xff',pos)
    if q<0: pos=len(b); break
    j=q+1
    while j<len(b) and b[j]==0xff: j+=1
    if j>=len(b): pos=len(b); break
    code=b[j]
    if code==0 or 0xd0<=code<=0xd7: pos=j+1; continue
    pos=q; in_entropy=False; break
   if pos>=len(b): break
  if b[pos]!=0xff: bad.append(f'non-marker byte at {pos}'); break
  start=pos
  while pos<len(b) and b[pos]==0xff: pos+=1
  if pos>=len(b): bad.append('trailing marker prefix'); break
  marker=b[pos]; pos+=1
  if marker==0xd9: eoi=pos; segments.append({'marker':'EOI','offset':start}); break
  if marker in (0xd8,0x01) or 0xd0<=marker<=0xd7:
   segments.append({'marker':f'FF{marker:02X}','offset':start,'length':0}); continue
  if pos+2>len(b): bad.append('short length'); break
  n=struct.unpack_from('>H',b,pos)[0]
  if n<2 or pos+n>len(b): bad.append(f'invalid segment length at {start}'); break
  data=b[pos+2:pos+n]; name=f'FF{marker:02X}'; ent={'marker':name,'offset':start,'length':n,'payload_bytes':len(data)}
  if marker==0xfe or 0xe0<=marker<=0xef:
   ent['prefix_hex']=data[:24].hex(); ent['payload_sha256']=sha(data)
   if marker==0xfe: ent['comment_preview']=data[:256].decode('latin1','replace')
   if marker==0xe1: ent['exif_signature']=data.startswith(b'Exif\0\0')
  if marker in (0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf) and len(data)>=6:
   ent['sof']={'precision':data[0],'height':int.from_bytes(data[1:3],'big'),'width':int.from_bytes(data[3:5],'big'),'components':data[5]}
  segments.append(ent); pos+=n
  if marker==0xda: scans+=1; in_entropy=True
 pil=Image.open(path); pil.load()
 return {'file':str(path.relative_to(ROOT)),'size_bytes':len(b),'sha256':sha(b),'format':pil.format,'mode':pil.mode,'dimensions':list(pil.size),'segments':segments,'scan_count':scans,'malformed':bad,'eoi_present':eoi is not None,'trailing_after_eoi_bytes':len(b)-(eoi or len(b)),'trailing_hex':b[eoi:eoi+64].hex() if eoi else '', 'pil_info':{k:str(v) for k,v in pil.info.items()},'exif_tags':{str(k):str(v)[:256] for k,v in pil.getexif().items()}}

def main():
 p_png=OUT/'cicada-reproduced.png'; p_jpg=OUT/'gematria-reproduced.jpg'
 report={'png':png_audit(p_png),'jpeg':jpeg_audit(p_jpg),'comparisons':[],'png_previews':create_png_previews(p_png)}
 pairs=[(p_png,ROOT/'archives/neuroretransmit-cicada/2013/003-twitter/decoded.png'),(p_jpg,ROOT/'archives/archive2/2013/additional images/Testout.jpg'),(p_jpg,ROOT/'archives/archive2/2014/additional images/Testout.jpg'),(p_jpg,ROOT/'archives/archive2/assets/2013/testout.jpg'),(p_jpg,ROOT/'archives/archive2/assets/2013/gematria-primus.jpg'),(p_jpg,ROOT/'archives/archive2/assets/2014/stage04/gematria-primus.jpg')]
 for a,c in pairs:
  if c.exists():
   ba,bc=a.read_bytes(),c.read_bytes(); ia,ic=Image.open(a).convert('RGBA'),Image.open(c).convert('RGBA')
   if ia.size==ic.size:
    import PIL.ImageChops as Ch
    diff=Ch.difference(ia,ic); extrema=diff.getextrema(); ex=diff.getbbox(); vals=list(diff.get_flattened_data()); mae=round(sum(sum(px) for px in vals)/(len(vals)*4*255),9); maxdiff=max(v[1] for v in extrema)
   else: ex='dimension mismatch'; mae=None; extrema=None; maxdiff=None
   report['comparisons'].append({'derived':str(a.relative_to(ROOT)),'archive':str(c.relative_to(ROOT)),'derived_sha256':sha(ba),'archive_sha256':sha(bc),'byte_identical':ba==bc,'decoded_pixel_bbox_diff':ex,'channel_difference_extrema':extrema,'max_channel_difference':maxdiff,'mean_absolute_channel_difference_0_to_1':mae})
 OUT.joinpath('image-container-audit.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 print(json.dumps(report,indent=2))
if __name__=='__main__': main()
