"""Final read-only cross-checks; never execute content obtained from the ISO."""
from pathlib import Path
import ast
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/iso-audit'

def read(name):
    return json.loads((OUT / name).read_text(encoding='utf-8'))

checks = {}
raw = (ROOT / 'archives/3301.iso').read_bytes()
checks['source_sha256_unchanged'] = hashlib.sha256(raw).hexdigest() == '784643558799dd8bb3e172f31df6d6ca2f397fd61cb8fc371bf930f1e5ae6b7f'
checks['source_size'] = len(raw) == 136398848
manifest = read('rootfs-manifest.json')
regular = [r for r in manifest if r['type'] == 'regular']
checks['regular_count'] = len(regular) == 612
bad_files = []
for r in regular:
    p = OUT / 'rootfs' / r['path']
    if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest() != r['sha256']:
        bad_files.append(r['path'])
checks['extracted_hashes_match_manifest'] = not bad_files
checks['no_extra_extracted_regular_files'] = sum(p.is_file() for p in (OUT / 'rootfs').rglob('*')) == 612
checks['signature_valid'] = read('signature-verification.json')['signature']['valid']
checks['signature_independent_rsa_valid'] = read('signature-independent.json')['rsa_signature_valid']
rows = read('phone-xor-audit.json')['rows']
checks['seven_successful_phone_reproductions_two_bad_transcriptions'] = sum(r['matches_expected_with_newline'] for r in rows) == 7 and len(rows) == 9
png = read('image-container-audit.json')['png']
checks['png_container_closes'] = png['all_chunk_crc_valid'] and png['trailing_after_iend_bytes'] == 0 and png['idat']['zlib_eof'] and png['idat']['unused_data_bytes'] == 0 and png['idat']['extra_decompressed_bytes'] == 0
audio = read('audio-audit.json')
checks['audio_frames_and_crcs'] = audio['mpeg_frames'] == 6397 and audio['unparsed_size'] == 0 and not audio['errors'] and audio['xing_lame']['music_crc16_valid'] and audio['xing_lame']['tag_crc16_valid']
boot = read('boot-raw-audit.json')
checks['loader_matches_official_baseline_outside_mastering_table'] = boot['baseline']['official_checksum_matches'] and boot['baseline']['equal_outside_boot_info_table']
checks['boot_pointers_length_and_checksum'] = all(boot['boot_info_table'][k] for k in ('checksum_matches','pvd_pointer_matches','catalog_and_directory_image_pointer_match','length_matches','loaded_bytes_match_file_prefix'))
checks['kernel_header_and_payload_bounds'] = all(boot['kernel_boot_header'][k] for k in ('file_length_matches_header','declared_payload_is_exact_complete_gzip','matches_previously_carved_elf','last4_equals_complemented_zlib_crc32'))
directory = read('directory-record-audit.json')
checks['directory_records_and_allocations'] = not directory['anomalies'] and not directory['extent_collisions'] and directory['record_count'] == 25 and not directory['path_tables']['cross_checks']
descriptor = read('descriptor-audit.json')
pvd = next(d for d in descriptor['descriptors'] if d['type'] == 1)
paired_fields = ('volume_space_size_both','volume_set_size_both','volume_sequence_both','block_size_both','path_table_size_both','root_extent_both','root_size_both','root_volume_seq_both')
checks['descriptor_duplicate_fields_and_path_tables'] = all(pvd[k][0] == pvd[k][1] for k in paired_fields) and not descriptor['directory_walk']['both_endian_record_mismatches'] and not descriptor['path_tables']['L_M_differences_including_name_parent_extent_extattr'] and not any(descriptor['path_tables']['table_directory_tree_differences'].values())
checks['descriptor_unused_bytes_and_namespaces'] = pvd['application_use_spaces'] == 512 and not any(raw[16*2048+a:16*2048+b].strip(b'\0') for a,b in ((7,8),(72,80),(88,120),(882,883),(1395,2048))) and not any(raw[18*2048+7:19*2048]) and descriptor['CD001_scan']['occurrences'] == 3 and len(boot['sector_aligned_volume_signatures']) == 3
framing = read('cpio-framing-audit.json')
bits = framing['gzip']['deflate_bitstream_audit']
checks['gzip_and_deflate_padding'] = framing['gzip']['crc32_valid'] and framing['gzip']['isize_valid'] and framing['gzip']['trailing_bytes_after_member_count'] == 0 and bits['parser_valid'] and bits['output_byte_count_accounted_for'] == 8324608 and bits['final_ignored_padding']['value'] == 0 and not any(p['value'] for p in bits['stored_alignment_padding_bits'])
checks['ignored_bit_detection_selfchecks'] = framing['gzip']['deflate_padding_bit_selfcheck']['passed']
checks['cpio_framing_and_names'] = framing['cpio']['nonzero_padding_byte_count'] == 0 and framing['cpio']['bytes_after_trailer_all_zero'] and not framing['cpio']['record_start_gap_anomalies'] and not framing['cpio']['name_encoding_issues'] and framing['cpio']['manifest_comparison']['all_shared_record_fields_match']
json_files = list(OUT.rglob('*.json'))
for p in json_files:
    json.loads(p.read_text(encoding='utf-8'))
checks['json_artifacts_parse'] = True
scripts = list((ROOT / 'codex-scripts').glob('iso_*.py')) + [ROOT / 'codex-scripts/image_container_audit.py', ROOT / 'codex-scripts/phone_xor_audit.py']
for p in scripts:
    ast.parse(p.read_text(encoding='utf-8'), filename=str(p))
checks['analysis_script_syntax'] = True
broken_links = []
for p in (ROOT / 'findings/2013/iso-static-audit.md', ROOT / 'findings/2013/iso-format-audit.md', OUT / 'README.md', ROOT / 'archives/ARCHIVE_INDEX.md'):
    for target in re.findall(r'\]\(([^)]+)\)', p.read_text(encoding='utf-8')):
        if target.startswith(('http:', 'https:', '#', 'mailto:')):
            continue
        target = target.strip('<>').split('#')[0]
        if not (p.parent / target).exists():
            broken_links.append({'document': str(p.relative_to(ROOT)), 'target': target})
checks['report_local_links_resolve'] = not broken_links
independent_files = []
for record in read('iso-inventory.json'):
    if record['flags'] & 2:
        continue
    selector = record['path'].rstrip('.')
    proc = subprocess.Popen(['C:/Program Files/7-Zip/7z.exe', 'e', '-so', '-spd', str(ROOT / 'archives/3301.iso'), selector], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    digest = hashlib.sha256(); size = 0
    for chunk in iter(lambda: proc.stdout.read(1024*1024), b''):
        digest.update(chunk); size += len(chunk)
    stderr = proc.stderr.read().decode('utf-8', 'replace'); code = proc.wait(timeout=30)
    proc.stdout.close(); proc.stderr.close()
    independent_files.append({'path': record['path'], 'seven_zip_selector': selector, 'returncode': code, 'bytes': size, 'sha256': digest.hexdigest(), 'matches': code == 0 and size == record['size'] and digest.hexdigest() == record['sha256'], 'stderr': stderr[:1000]})
checks['all_11_files_match_independent_7zip_reader'] = len(independent_files) == 11 and all(f['matches'] for f in independent_files)
native_tests = {}
for label, p in [('iso', ROOT / 'archives/3301.iso'), ('cpio', OUT / 'initramfs.cpio')]:
    result = subprocess.run(['C:/Program Files/7-Zip/7z.exe', 't', str(p)], capture_output=True, text=True, errors='replace', timeout=120)
    (OUT / ('7zip-' + label + '-test.txt')).write_text(result.stdout + result.stderr, encoding='utf-8')
    native_tests[label] = {'returncode': result.returncode, 'log': '7zip-' + label + '-test.txt'}
    checks['independent_7zip_' + label + '_test'] = result.returncode == 0
result = {'scope': 'Read-only final output consistency and independent archive-parser checks; no ISO code execution.', 'checks': checks, 'all_checks_pass': all(checks.values()), 'bad_extracted_files': bad_files, 'broken_links': broken_links, 'json_artifacts_checked': len(json_files), 'scripts_syntax_checked': len(scripts), 'native_archive_tests': native_tests, 'independent_iso_file_streams': independent_files}
(OUT / 'verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result, indent=2))
if not result['all_checks_pass']:
    raise SystemExit(1)
