"""Copy the ISO audit into a portable bundle; never execute copied material."""
from pathlib import Path
import argparse, hashlib, json, os, re, shutil
from urllib.parse import quote, unquote, urlsplit

ROOT=Path(__file__).resolve().parents[1]
STAGE=ROOT/'tmp/iso-analysis-export'
DEST=Path('C:/Users/crash/OneDrive/Desktop/3301_ISO_Analysis')
MAP=ROOT/'output/iso-audit/export-source-link-map.json'
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def safe_dest(base, rel):
    p=base/rel
    if not p.resolve().is_relative_to(base.resolve()):raise ValueError('Destination escapes bundle')
    return p
def local_href(document, target):
    return quote(os.path.relpath(target,document.parent).replace('\\','/'),safe='/#-._~')

def md_links(text):
    # Balanced parentheses support URLs containing parenthesized wiki titles.
    pattern=re.compile(r'(!?\[[^\]\n]*\])\(')
    for m in pattern.finditer(text):
        p=m.end();start=p;depth=1
        while p<len(text) and depth:
            if text[p]=='\\':p+=2;continue
            if text[p]=='(':depth+=1
            elif text[p]==')':depth-=1
            if depth:p+=1
        if depth==0:yield m.start(),p+1,m.group(1),text[start:p]

def stage():
    linkmap=json.loads(MAP.read_text(encoding='utf-8'))
    links={k:v for k,v in linkmap['links'].items() if v}
    selected={}
    for directory in ('output/iso-audit','reference-docs/iso-format-baselines'):
        for p in (ROOT/directory).rglob('*'):
            if p.is_symlink():raise ValueError('Unexpected symlink in analysis outputs')
            if p.is_file():selected[p.relative_to(ROOT).as_posix()]=p
    for p in (ROOT/'findings/2013').glob('iso-*.md'):
        selected[p.relative_to(ROOT).as_posix()]=p
    names=set()
    for p in [s for s in selected.values() if s.suffix=='.md']:
        names.update(n for n in re.findall(r'\b[\w-]+\.py\b',p.read_text(encoding='utf-8')) if (ROOT/'codex-scripts'/n).is_file())
    for name in sorted(names):selected['codex-scripts/'+name]=ROOT/'codex-scripts'/name
    selected['codex-scripts/iso_export_bundle.py']=Path(__file__).resolve()
    selected['archives/3301.iso']=ROOT/'archives/3301.iso'
    STAGE.mkdir(parents=True,exist_ok=True)
    for rel,source in selected.items():
        target=safe_dest(STAGE,rel);target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target)
    rewritten=[];unresolved_sources=set()
    def archive_url(citation):
        if citation in links:return links[citation]
        normalized=citation.replace('\\','/')
        if normalized in links:return links[normalized]
        return None
    def convert_code(match,doc):
        token=match.group(1)
        if token in ('.','..'):return match.group(0)
        if token=='archives/ARCHIVE_INDEX.md':
            return '['+token+']('+local_href(doc,STAGE/'SOURCES.md')+')'
        url=archive_url(token)
        if url:return '['+token+']('+url+')'
        if token.startswith('archives/') and token!='archives/3301.iso':
            unresolved_sources.add(token);return match.group(0)
        # Reference labels become links only when their exact bundled file exists.
        candidates=[STAGE/token.replace('\\','/'),doc.parent/token.replace('\\','/')]
        if token.endswith('.py'):candidates.append(STAGE/'codex-scripts'/token)
        for target in candidates:
            if target.exists() and target.resolve().is_relative_to(STAGE.resolve()):
                return '['+token+']('+local_href(doc,target)+')'
        return match.group(0)
    for rel in selected:
        if not rel.endswith('.md') or rel.startswith(('output/iso-audit/rootfs/','output/iso-audit/iso-files/')):continue
        doc=STAGE/rel;text=doc.read_text(encoding='utf-8');original=text
        # Convert exact source citations in prose without touching fenced code.
        parts=re.split(r'(^```[^\n]*\n.*?^```\s*$)',text,flags=re.M|re.S)
        for i in range(0,len(parts),2):
            spans=[(a,b) for a,b,_,_ in md_links(parts[i])]
            replacements=[]
            for m in re.finditer(r'`([^`\n]+)`',parts[i]):
                if not any(a<=m.start()<b for a,b in spans):
                    replacements.append((m.start(),m.end(),convert_code(m,doc)))
            for a,b,value in reversed(replacements):parts[i]=parts[i][:a]+value+parts[i][b:]
        text=''.join(parts)
        edits=[]
        for a,b,label,target in md_links(text):
            target=target.strip().strip('<>')
            if target.startswith(('http:','https:','mailto:','#')):continue
            url=archive_url(target)
            if url:edits.append((a,b,label+'('+url+')'));continue
            pathpart,sep,fragment=target.partition('#')
            path=unquote(pathpart)
            old=(ROOT/rel).parent/path
            if old.exists() and old.resolve().is_relative_to(ROOT.resolve()):
                root_rel=old.resolve().relative_to(ROOT.resolve()).as_posix()
                if root_rel.startswith('archives/') and root_rel!='archives/3301.iso':
                    url=archive_url(root_rel)
                    if url:edits.append((a,b,label+'('+url+')'));continue
                copied=STAGE/root_rel
                if copied.exists():edits.append((a,b,label+'('+local_href(doc,copied)+(sep+fragment if sep else '')+')'));continue
            # Repair the pre-existing splash link that incorrectly repeats output/.
            if 'output/iso-audit/' in path:
                copied=STAGE/('output/iso-audit/'+path.split('output/iso-audit/',1)[1])
                if copied.exists():edits.append((a,b,label+'('+local_href(doc,copied)+(sep+fragment if sep else '')+')'))
        for a,b,replacement in reversed(edits):text=text[:a]+replacement+text[b:]
        if text!=original:
            doc.write_text(text,encoding='utf-8');rewritten.append(rel)
    source_notes='\n'.join('- '+citation+': '+note for citation,note in linkmap.get('mapping_notes',{}).items())
    (STAGE/'SOURCES.md').write_text('# Archive and reference sources\n\nArchive citations use web links, pinned to the checked-out Git commit or captured wiki revision where available. Original local paths and XML line numbers remain citation labels; XML lines do not correspond to web-page line anchors.\n\n'+''.join('- ['+citation+']('+url+')\n' for citation,url in sorted(links.items()))+'\nThe original workspace index `archives/ARCHIVE_INDEX.md` has no verified public URL. Its bundle citation points here; source repositories and the original ISO are recorded in [the source map](output/iso-audit/export-source-link-map.json) and [the copy manifest](export-manifest.json).\n\nMapping caveats:\n\n'+source_notes+'\n\nThe machine-readable reports preserve original source paths as forensic provenance. Current web availability is distinct from the archived snapshot.\n',encoding='utf-8')
    (STAGE/'README.md').write_text('''# 3301 ISO analysis

Copied on 2026-10-10 from the completed static audit. Start with:

- [Content, documentation and inode report](findings/2013/iso-static-audit.md)
- [Low-level ISO/filesystem format report](findings/2013/iso-format-audit.md)
- [All output, extracted artifacts and evidence](output/iso-audit/README.md)
- [Custom-file metadata](output/iso-audit/custom-file-metadata.md)
- [Archive citations and web sources](SOURCES.md)
- [Upstream format references](reference-docs/iso-format-baselines/README.md)
- [Original ISO](archives/3301.iso)
- [Copy integrity and local-link verification](export-verification.json)
- [Full copy manifest](export-manifest.json)

The folder preserves the source project's relative layout. All generated outputs,
612 extracted rootfs regular files, 11 extracted ISO files, analysis scripts,
upstream baseline material and the original ISO are included. Raw binary and
machine-readable evidence bytes are unchanged. Report Markdown was adapted to
make links portable and archive citations clickable on the web.

Original acquisition paths and snapshot line references in JSON/CSV/logs are
preserved as evidence, not changed to claim a different acquisition location.
The scripts are included as source; some historical reproduction scripts require
additional archive repositories or wiki/IRC snapshots from the original project.
Those external source archives are linked through SOURCES.md rather than copied
wholesale. The original project's full index is not a bundle dependency.

The ISO, extracted executables and source archives remain untrusted data. No
contained code was run during this copy. The original analysis and archives
remain in their existing locations.
''',encoding='utf-8')
    generated=('README.md','SOURCES.md')
    expected=set(selected)|set(generated)|{'export-manifest.json','export-verification.json'}
    unexpected=[str(p.relative_to(STAGE)) for p in STAGE.rglob('*') if p.is_file() and p.relative_to(STAGE).as_posix() not in expected]
    if unexpected:raise ValueError('Unexpected staging files: '+repr(unexpected))
    files=[]
    for rel in sorted(set(selected)|set(generated)):
        target=STAGE/rel;entry={'path':rel,'bytes':target.stat().st_size,'sha256':digest(target)}
        if rel in selected:
            entry['source_path']=str(selected[rel]);entry['source_sha256']=digest(selected[rel]);entry['changed_for_portable_links']=entry['sha256']!=entry['source_sha256']
            if entry['changed_for_portable_links'] and not rel.endswith('.md'):raise ValueError('Non-Markdown evidence changed')
        else:entry['generated_for_export']=True
        files.append(entry)
    manifest={'destination':str(DEST),'source_project':str(ROOT),'files':files,'portable_report_files':rewritten,'unresolved_source_citations':sorted(unresolved_sources),'archive_web_link_count':len(links),'scope':'Byte-preserving copy except portable Markdown links and generated bundle navigation.'}
    (STAGE/'export-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
    # The navigation links to the verification artifact that this check produces.
    (STAGE/'export-verification.json').write_text('{}\n',encoding='utf-8')
    verify(STAGE,manifest,write=True)
    print(json.dumps({'stage':str(STAGE),'files':len(files),'bytes':sum(f['bytes'] for f in files),'rewritten_reports':len(rewritten),'unresolved_source_citations':sorted(unresolved_sources)},indent=2))

def verify(base,manifest,write=False):
    bad_hashes=[f['path'] for f in manifest['files'] if not (base/f['path']).is_file() or digest(base/f['path'])!=f['sha256']]
    broken=[];local_count=0;web_count=0
    for doc in base.rglob('*.md'):
        if doc.relative_to(base).as_posix().startswith(('output/iso-audit/rootfs/','output/iso-audit/iso-files/')):continue
        for _,_,_,target in md_links(doc.read_text(encoding='utf-8')):
            target=target.strip().strip('<>')
            if target.startswith(('http:','https:','mailto:')):web_count+=1;continue
            if target.startswith('#'):continue
            local_count+=1;path=unquote(target.split('#',1)[0]);p=doc.parent/path
            if not p.resolve().is_relative_to(base.resolve()) or not p.exists():broken.append({'document':doc.relative_to(base).as_posix(),'target':target})
    result={'all_checks_pass':not bad_hashes and not broken,'files_hash_verified':len(manifest['files']),'copied_bytes':sum(f['bytes'] for f in manifest['files']),'changed_markdown_files':sum(f.get('changed_for_portable_links',False) for f in manifest['files']),'bad_hashes':bad_hashes,'broken_local_links':broken,'local_links_checked':local_count,'web_links':web_count,'web_link_scope':'Source mapping uses Git remotes/commits and captured wiki revision IDs; web targets were not all individually fetched.'}
    if write:(base/'export-verification.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if not result['all_checks_pass']:raise ValueError(json.dumps(result))
    return result

def publish():
    if DEST.absolute()!=Path('C:/Users/crash/OneDrive/Desktop/3301_ISO_Analysis').absolute() or DEST.is_symlink():raise ValueError('Unexpected destination')
    manifest=json.loads((STAGE/'export-manifest.json').read_text(encoding='utf-8'));verify(STAGE,manifest)
    files=[f['path'] for f in manifest['files']]+['export-manifest.json','export-verification.json']
    # Preflight every existing target before writing; never overwrite different files.
    for rel in files:
        target=safe_dest(DEST,rel)
        if target.exists() and (not target.is_file() or digest(target)!=digest(STAGE/rel)):
            raise ValueError('Destination already contains a different file: '+str(target))
    DEST.mkdir(parents=True,exist_ok=True)
    for rel in files:
        target=safe_dest(DEST,rel);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(STAGE/rel,target)
    result=verify(DEST,manifest)
    print(json.dumps({'destination':str(DEST),**result},indent=2))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=('stage','publish'));args=parser.parse_args()
    stage() if args.mode=='stage' else publish()
