from pathlib import Path
import hashlib, json

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'output/iso-audit'
DATA=OUT/'iso-files'/'DATA'
README='archives/neuroretransmit-cicada/2013/006-third-onion/README.md'
WIKI='archives/uncovering-cicada-wiki-20260810/export/uncovering-cicada-wiki-export.xml'
# Values transcribed from the cited documentary sources. No network endpoint is contacted.
rows=[
 {'label':'Dallas README corrected offset','dataset':17,'offset':33461,'hex':'f6a2d0a48e1b1ae40cbd454f77baa7d2557683d0cd4998','expected':'y2wyuvrqraowagc5.onion','source':f'{README}: All locations list'},
 {'label':'Dallas wiki initial offset','dataset':17,'offset':16433,'hex':'f6a2d0a48e1b1ae40cbd454f77baa7d2557683d0cd4998','expected':'y2wyuvrqraowagc5.onion','source':f'{WIKI}:31632'},
 {'label':'Okinawa','dataset':13,'offset':37861,'hex':'f286b8438cb85eb191ec7bf10a28a54ec06f9a27eb91c5','expected':'wzwmcwmsk5cb7gjn.onion','source':f'{README}: All locations list'},
 {'label':'Moscow','dataset':13,'offset':1111111,'hex':'c657b2707c4266fda4af4a83acf19cc46e69540c0bc5da','expected':'qw7mhchzvuq6f2mf.onion','source':f'{README}: All locations list'},
 {'label':'Little Rock','dataset':13,'offset':13831,'hex':'5edb5e8029dd2182560da925ec6cd3e1257efc0b8328b4','expected':'4l6uipnstbggwjyv.onion','source':f'{README}: All locations list'},
 {'label':'Annapolis README transcription','dataset':17,'offset':77977,'hex':'d5a6cb76e55a2166bd6a4d78857ec1f68ea6afa97380','expected':'erwfcsdvx6pm2rsk.onion','source':f'{README}: All locations list'},
 {'label':'Annapolis corrected wiki ciphertext','dataset':17,'offset':77977,'hex':'d5a6cb76e55a2166bd6a4d078857ec1f68ea6afa973868','expected':'erwfcsdvx6pm2rsk.onion','source':f'{WIKI}:34685'},
 {'label':'Portland','dataset':13,'offset':12821,'hex':'28c07e1b102d4d5c4c1a376e064477e1416fcc94928765','expected':'gbyh7znm6c7ezsmr.onion','source':f'{README}: All locations list'},
 {'label':'Columbus','dataset':17,'offset':617,'hex':'d4b10626d65995e8fb010f4388787d56433f90c6df8d8d','expected':'ll5afyskb6v6g7ga.onion','source':f'{README}: All locations list'},
]
results=[]
for row in rows:
    stream=(DATA/f"560.{row['dataset']}").read_bytes()
    cipher=bytes.fromhex(row['hex']); off=row['offset']
    window=stream[off:off+len(cipher)]
    clear=bytes(a^b for a,b in zip(window,cipher))
    expected=row['expected'].encode('ascii')
    recovered=bytes(a^b for a,b in zip(window,expected+b'\n')) if off+len(expected)+1<=len(stream) else b''
    results.append({**row,'ciphertext_length':len(cipher),'window_length':len(window),'plaintext_hex':clear.hex(),'plaintext_ascii':clear.decode('ascii','replace'),'matches_expected_with_newline':clear==expected+b'\n','recovered_ciphertext_for_expected_onion_plus_lf':recovered.hex(),'recovered_ciphertext_matches_supplied':recovered==cipher,'stream_sha256':hashlib.sha256(stream).hexdigest()})

# Verify the offset 12821 row also agrees with the earlier derived data artifact.
summary={'scope':'Static XOR of the cited ciphertexts against extracted ISO DATA streams; no calling phone numbers or visiting onion services.','sources':{'third_onion_readme':README,'wiki_export':WIKI},'rows':results,'dataset_files':{str(n):{'path':str((DATA/f'560.{n}').relative_to(ROOT)),'size':(DATA/f'560.{n}').stat().st_size,'sha256':hashlib.sha256((DATA/f'560.{n}').read_bytes()).hexdigest()} for n in (13,17)}}
(OUT/'phone-xor-audit.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
print([(r['label'],r['plaintext_ascii'].encode('ascii','replace').decode('ascii'),r['matches_expected_with_newline']) for r in results])
