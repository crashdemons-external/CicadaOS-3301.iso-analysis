"""Cross-check the parsed ISO RSA signature with bundled cryptography/OpenSSL.

Uses the computed OpenPGP digest as a prehashed input; packet/cleartext handling
is covered by iso_signature_audit.py. No packages or source binaries installed.
"""
from pathlib import Path
import json, runpy
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes
ROOT=Path(__file__).resolve().parents[1]
s=runpy.run_path(str(ROOT/'codex-scripts/iso_signature_audit.py'))
key=rsa.RSAPublicNumbers(s['e'],s['n']).public_key()
signature=s['rsig'].to_bytes((s['n'].bit_length()+7)//8,'big')
key.verify(signature,s['digest'],padding.PKCS1v15(),utils.Prehashed(hashes.SHA1()))
r={'rsa_signature_valid':True,'cryptography_version':cryptography.__version__,
   'key_fingerprint':s['fpr'],'verified_digest':s['digest'].hex(),
   'scope':'Independent RSA/PKCS#1 v1.5 operation over the OpenPGP digest. Packet parsing/canonicalization uses the separately reviewed stdlib verifier.'}
(ROOT/'output/iso-audit/signature-independent.json').write_text(json.dumps(r,indent=2),encoding='utf-8')
print(json.dumps(r,indent=2))
