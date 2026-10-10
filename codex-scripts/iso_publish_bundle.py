"""Prepare and apply the authorized GitHub publication, omitting the ISO bytes."""
from pathlib import Path
import argparse, json, shutil
from iso_export_bundle import digest, verify, safe_dest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path('C:/Users/crash/OneDrive/Desktop/3301_ISO_Analysis')
STAGE=ROOT/'tmp/iso-github-publication'
ISO='archives/3301.iso'
ISO_HASH='784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f'
LFS=['output/iso-audit/iso-files/DATA/560.13','output/iso-audit/audio-spectral-data.npz']

def prepare():
    original=json.loads((SOURCE/'export-manifest.json').read_text(encoding='utf-8'))
    verify(SOURCE,original)
    selected=[f for f in original['files'] if f['path']!=ISO]
    expected={f['path'] for f in original['files']}|{'export-manifest.json','export-verification.json'}
    extra=[p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file() and p.relative_to(SOURCE).as_posix() not in expected]
    if extra:raise ValueError('Unexpected source files: '+repr(extra))
    STAGE.mkdir(parents=True,exist_ok=True)
    for f in selected:
        source=SOURCE/f['path'];target=safe_dest(STAGE,f['path'])
        if source.is_symlink():raise ValueError('Unexpected symlink')
        if source.suffix.lower()=='.iso' or f['sha256']==ISO_HASH:raise ValueError('An ISO copy would be published')
        target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,target)
    (STAGE/'archives').mkdir(exist_ok=True)
    (STAGE/'archives/3301.iso.sha256').write_text(ISO_HASH+'  3301.iso\n',encoding='utf-8')
    (STAGE/'archives/3301.iso.md').write_text('''# Input ISO identity

Filename: `3301.iso`. The ISO itself is intentionally excluded from this repository.

```text
MD5     74062dee4093c6ca0340cda23f0e994b
SHA1    df433cba87644b35cbc47f702a02e2b58d90af6a
SHA256  784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f
```

[SHA-256 checksum file](3301.iso.sha256).

To repeat checks requiring the original image, provide your own matching file at
`archives/3301.iso`. Source provenance is in [SOURCES.md](../SOURCES.md).
''',encoding='utf-8')
    readme=(STAGE/'README.md').read_text(encoding='utf-8')
    readme=readme.replace('[Original ISO](archives/3301.iso)','[ISO filename and hashes](archives/3301.iso.md)')
    readme=readme.replace('[Full copy manifest]','[Publication copy manifest]')
    readme=readme.replace('upstream baseline material and the original ISO are included. Raw binary and','and upstream baseline material are included. The original ISO is excluded;\nonly its filename and hashes are retained. Raw binary and')
    readme+='''
The two large generated/extracted artifacts are stored using Git LFS. After
cloning, run `git lfs pull` to obtain their bytes. Their original hashes remain
in the evidence manifests. GitHub's [large-file documentation](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)
describes the regular Git file limit.

The verification and publication manifest describe the published files.
Historical analysis verification reports under `output/iso-audit/` describe
the original analysis run, which had the matching ISO available locally.
'''
    (STAGE/'README.md').write_text(readme,encoding='utf-8')
    (STAGE/'.gitignore').write_text('# Keep the original input and any ISO copies out of Git.\n*.[iI][sS][oO]\n__pycache__/\n*.py[cod]\n',encoding='utf-8')
    (STAGE/'.gitattributes').write_text('# Preserve evidence bytes without line-ending normalization.\n* -text\n'+''.join(p+' filter=lfs diff=lfs merge=lfs -text\n' for p in LFS),encoding='utf-8')
    target=STAGE/'codex-scripts/iso_publish_bundle.py';shutil.copy2(Path(__file__).resolve(),target)
    additions={'archives/3301.iso.sha256','archives/3301.iso.md','.gitignore','.gitattributes','codex-scripts/iso_publish_bundle.py'}
    paths={f['path'] for f in selected}|additions
    extra=[p.relative_to(STAGE).as_posix() for p in STAGE.rglob('*') if p.is_file() and p.relative_to(STAGE).as_posix() not in paths|{'export-manifest.json','export-verification.json'}]
    if extra:raise ValueError('Unexpected publication files: '+repr(extra))
    originals={f['path']:f for f in selected};files=[]
    for rel in sorted(paths):
        p=STAGE/rel;entry=dict(originals.get(rel,{}));entry.update(path=rel,bytes=p.stat().st_size,sha256=digest(p))
        if rel not in originals:entry['generated_for_publication']=True
        elif entry['sha256']!=originals[rel]['sha256']:
            if rel!='README.md':raise ValueError('Unexpected changed evidence')
            entry['changed_for_iso_exclusion']=True
        files.append(entry)
    manifest=dict(original);manifest.update(files=files,scope='Publication excludes the input ISO; evidence bytes preserved, with navigation and Git LFS configuration added.',excluded_inputs=[{'filename':'3301.iso','path':ISO,'sha256':ISO_HASH}],git_lfs_paths=LFS)
    (STAGE/'export-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    (STAGE/'export-verification.json').write_text('{}\n',encoding='utf-8')
    result=verify(STAGE,manifest,write=True)
    # Preserve exact preflight values outside the publication tree.
    preflight={f['path']:f['sha256'] for f in original['files']}
    preflight.update({n:digest(SOURCE/n) for n in ('export-manifest.json','export-verification.json')})
    (ROOT/'tmp/iso-publication-preflight.json').write_text(json.dumps(preflight,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

def apply():
    manifest=json.loads((STAGE/'export-manifest.json').read_text(encoding='utf-8'));verify(STAGE,manifest)
    preflight=json.loads((ROOT/'tmp/iso-publication-preflight.json').read_text(encoding='utf-8'))
    files=[f['path'] for f in manifest['files']]+['export-manifest.json','export-verification.json']
    for rel in files:
        target=safe_dest(SOURCE,rel)
        if target.exists() and (not target.is_file() or digest(target) not in (preflight.get(rel),digest(STAGE/rel))):
            raise ValueError('Refusing to overwrite an unexpected file: '+str(target))
    for rel in files:
        target=safe_dest(SOURCE,rel);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STAGE/rel,target)
    print(json.dumps(verify(SOURCE,manifest),indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=('prepare','apply'));args=p.parse_args()
    prepare() if args.mode=='prepare' else apply()
