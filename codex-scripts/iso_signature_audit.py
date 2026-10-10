import pathlib,base64,re,hashlib,json,struct,datetime,math
R=pathlib.Path('.'); root=R/'output/iso-audit/rootfs'; keypath=R/'archives/neuroretransmit-cicada/cicada-accounts-identities/cicada.asc'; sigpath=root/'usr/local/bin/message.txt.asc'; msgpath=root/'usr/local/bin/message.txt'
def armor(path,kind):
 s=path.read_text(encoding='ascii'); body=s.split('-----',2)[2] if False else None
 lines=s.splitlines(); start=next(i for i,x in enumerate(lines) if x.startswith('-----BEGIN PGP SIGNATURE-----')) if kind=='message' else next(i for i,x in enumerate(lines) if x.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')); end=next(i for i,x in enumerate(lines[start+1:],start+1) if x.startswith('-----END PGP ')); payload=''.join(x.strip() for x in lines[start+1:end] if x.strip() and not x.startswith('=') and ':' not in x); return base64.b64decode(payload)
def packets(data):
 out=[]; i=0
 while i<len(data):
  h=data[i]; i+=1
  if not h&0x80: raise ValueError('bad packet header')
  if h&0x40:
   tag=h&63; c=data[i]; i+=1
   if c<192:n=c
   elif c<224:n=((c-192)<<8)+data[i]+192;i+=1
   elif c==255:n=int.from_bytes(data[i:i+4],'big');i+=4
   else: raise ValueError('partial body unsupported')
  else:
   tag=(h>>2)&15; typ=h&3
   if typ==0:n=data[i];i+=1
   elif typ==1:n=int.from_bytes(data[i:i+2],'big');i+=2
   elif typ==2:n=int.from_bytes(data[i:i+4],'big');i+=4
   else: raise ValueError('indeterminate packet length')
  out.append((tag,data[i:i+n]));i+=n
 return out
def mpi(b,pos):
 bits=int.from_bytes(b[pos:pos+2],'big'); n=(bits+7)//8; v=int.from_bytes(b[pos+2:pos+2+n],'big');return v,pos+2+n,b[pos:pos+2+n]
def u32(b):return int.from_bytes(b,'big')
kp=packets(armor(keypath,'key')); primary=next(b for t,b in kp if t==6); uid=next((b.decode('utf8','replace') for t,b in kp if t==13),None)
assert primary[0]==4; n,p,mpi_n=mpi(primary,6); e,p,mpi_e=mpi(primary,p)
fpr=hashlib.sha1(b'\x99'+len(primary).to_bytes(2,'big')+primary).hexdigest().upper(); keyid=fpr[-16:]
raw=armor(sigpath,'message'); blocks=packets(raw); sb=next(b for t,b in blocks if t==2); assert sb[0]==4
version,stype,pub,halgo=sb[:4]; hlen=int.from_bytes(sb[4:6],'big'); hashed=sb[6:6+hlen]; off=6+hlen; ulen=int.from_bytes(sb[off:off+2],'big'); unhashed=sb[off+2:off+2+ulen]; off+=2+ulen; left=sb[off:off+2]; off+=2; rsig,off,rsig_mpi=mpi(sb,off)
# Parse creation-time subpacket
sp=[];i=0
while i<len(hashed):
 c=hashed[i];i+=1
 if c<192: ln=c
 elif c<255: ln=((c-192)<<8)+hashed[i]+192;i+=1
 else: ln=int.from_bytes(hashed[i:i+4],'big');i+=4
 d=hashed[i:i+ln];i+=ln
 if d:sp.append((d[0]&127,d[1:]))
created=next((u32(d) for t,d in sp if t==2 and len(d)==4),None)
armor_text=sigpath.read_text(encoding='utf8'); clear=armor_text.split('-----BEGIN PGP SIGNED MESSAGE-----',1)[1].split('-----BEGIN PGP SIGNATURE-----',1)[0]
lines=clear.splitlines(); i=0
while i<len(lines) and not lines[i]: i+=1
while i<len(lines) and lines[i]: i+=1
i+=1  # separator blank after armor headers
bodylines=lines[i:]
# Cleartext signature canonicalization trims trailing horizontal whitespace and uses CRLF.
canon='\r\n'.join(re.sub(r'[ \t]+$','',x) for x in bodylines)
trailer=bytes([4,255])+(6+hlen).to_bytes(4,'big'); digest=hashlib.sha1(canon.encode()+sb[:6+hlen]+trailer).digest()
# SHA1 DigestInfo DER
prefix=bytes.fromhex('3021300906052b0e03021a05000414'); emlen=(n.bit_length()+7)//8; em=pow(rsig,e,n).to_bytes(emlen,'big'); tail=prefix+digest; expected_em=b'\x00\x01'+b'\xff'*(emlen-len(tail)-3)+b'\x00'+tail
valid=pub==1 and halgo==2 and left==digest[:2] and em==expected_em
unsigned=msgpath.read_text(encoding='utf8'); unsigned_lines=unsigned.splitlines()
unsignedcanon='\r\n'.join(re.sub(r'[ \t]+$','',x) for x in unsigned_lines)
unsignedcanon_without_first_blank='\r\n'.join(re.sub(r'[ \t]+$','',x) for x in unsigned_lines[1:])
source_comparison=canon==unsignedcanon
source_comparison_without_first_blank=canon==unsignedcanon_without_first_blank
source_comparison_without_first_blank=canon==unsignedcanon_without_first_blank
# hashes across known archived representations
names=['usr/local/bin/cicada','usr/local/bin/prime_echo','usr/local/bin/message.txt','usr/local/bin/message.txt.asc','tmp/folly','tmp/wisdom']
locations=[R/'archives/neuroretransmit-cicada/2013/002-3301/rootfs-contents',R/'archives/neuroretransmit-cicada/2013/002-3301/rootfs-modified',R/'archives/archive2/2013/additional files/Cicada OS/cicados',R/'archives/archive2/assets/2013/cicados',R/'archives/archive3/assets/2013/cicados']
comp=[]
for name in names:
 srcs=[]
 for loc in locations:
  candidates=[loc/name]
  if name.startswith('usr/local/bin/'): candidates.append(loc/'usr_local_bin'/name.rsplit('/',1)[-1])
  dst=(root/name).read_bytes(); dh=hashlib.sha256(dst).hexdigest()
  for f in candidates:
   if f.is_file():
    sb=f.read_bytes(); textlike=b'\0' not in sb and b'\0' not in dst
    norm=lambda b: b.replace(b'\r\n',b'\n').replace(b'\r',b'\n')
    srcs.append({'path':str(f),'sha256':hashlib.sha256(sb).hexdigest(),'exact_bytes_same':sb==dst,'normalized_line_endings_same':norm(sb)==norm(dst) if textlike else None})
 comp.append({'path':name,'rootfs_sha256':hashlib.sha256((root/name).read_bytes()).hexdigest(),'archive_copies':srcs})
result={'scope':'stdlib-only local packet parsing and public-key signature verification; no execution','signature':{'valid':valid,'signature_type':stype,'public_key_algorithm':pub,'hash_algorithm':halgo,'key_fingerprint_v4_sha1':fpr,'key_id':keyid,'key_user_id':uid,'signature_created_unix':created,'signature_created_utc':datetime.datetime.fromtimestamp(created,datetime.timezone.utc).isoformat() if created else None,'canonical_text_sha1':digest.hex(),'signed_cleartext_exactly_matches_message_txt':source_comparison,'matches_after_removing_one_leading_blank_line':source_comparison_without_first_blank,'rsa_decoded_sha1_digest':em[-20:].hex(),'rsa_modulus_bits':n.bit_length(),'signature_mpi_bits':rsig.bit_length(),'verification_method':'OpenPGP v4 canonical-text signature; SHA-1 digest with v4 hashed-subpacket trailer; RSA public operation and PKCS#1 v1.5 SHA-1 DigestInfo comparison'},'archive_hash_comparisons':comp,'caveats':['A mathematically valid signature binds the cleartext to this public key; it does not by itself authenticate the key provenance or identity.','Signature timestamp is signer-supplied metadata.','Archive comparison only covers exact paths found in the listed local copies.']}
out=R/'output/iso-audit/signature-verification.json';out.write_text(json.dumps(result,indent=2)+'\n')
md=f'''# OpenPGP signature and rootfs copy verification\n\nA standard-library-only Python script parsed the armored key/message packets and checked the RSA signature mathematically. No extracted code or binary was executed; no external crypto package or system `gpg` was used.\n\n## Signature result\n\n- Signature valid: **{valid}** using OpenPGP v4 canonical text, SHA-1 and RSA PKCS#1 v1.5.\n- Signing public key fingerprint (v4 SHA-1): `{fpr}`; key ID `{keyid}`; user ID `{uid}`.\n- Signature creation time metadata: {result['signature']['signature_created_utc']} (signer-supplied).\n- Canonical signed cleartext exactly matches `message.txt`: **{source_comparison}**. After removing one leading blank line from `message.txt`, the bytes match: **{source_comparison_without_first_blank}**. This is presentation padding; visible text is unchanged.\n- SHA-1 decoded from the RSA PKCS#1 encoded message: `{em[-20:].hex()}`.\n\nA valid signature shows that the signed message verifies under the supplied public key. It does not independently authenticate the public key’s identity or provenance.\n\n## Archive copy comparisons\n\nSHA-256 hashes were compared for `cicada`, `prime_echo`, `message.txt`, `message.txt.asc`, `folly`, and `wisdom` against copies under neuroretransmit-cicada, archive2, and archive3 where present. The JSON records each located path and equality result.\n\n'''
for row in comp:
 md+=f"- `{row['path']}`: "+('; '.join(f"{x['path']} exact={x['exact_bytes_same']} line-endings-normalized={x['normalized_line_endings_same']}" for x in row['archive_copies']) or 'no alternate exact-path copy found')+'\n'
md+='\nThe signature verifier and full machine-readable results are in `codex-scripts/iso_signature_audit.py` and `output/iso-audit/signature-verification.json`. Hash scope is limited to exact local paths present in the searched archive copies.\n'
with (R/'output/iso-audit/signature-verification.md').open('w',encoding='utf-8',newline='\n') as report:
 report.write(md)


