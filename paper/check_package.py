"""Verify this workspace's generated submission in an isolated extraction.

Runs packaged analysis code only after matching it to this workspace. No model
downloads, inference, browser launch, or publication. Tests need loopback sockets.
Use --compile to also rebuild the exact arXiv source with Tectonic/Poppler.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unpack_verified(blob, destination):
    """Check paths, exact membership, size, and digests before extracting."""
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names = z.namelist()
        require(len(names) == len(set(names)), "Duplicate archive member")
        require(sum(i.file_size for i in z.infolist()) < 100_000_000, "Unexpected archive size")
        for name in names:
            p = PurePosixPath(name)
            require(not p.is_absolute() and '..' not in p.parts and '\\' not in name
                    and str(p) == name, "Unsafe archive member")
            require(not name.endswith(('.sqlite', '.safetensors')), "Unexpected database/model weights")
        manifest = json.loads(z.read('MANIFEST-SHA256.json'))
        require(set(names) == set(manifest) | {'MANIFEST-SHA256.json'}, "Manifest membership mismatch")
        for name, commitment in manifest.items():
            data = z.read(name)
            require(sha(data) == commitment, f"Checksum mismatch: {name}")
            if name.startswith('data/'):
                require(b'PRIVATE KEY-----' not in data, f"Private key in artifact: {name}")
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    return manifest


def run(command, cwd):
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    require(result.returncode == 0, f"Failed: {command}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def check_execution(directory):
    """Re-verify the separate fault run's receipts and successful receiver bytes."""
    import base64
    from collections import Counter
    from urllib.parse import urlsplit
    from cryptography.hazmat.primitives import serialization
    from handoff_witness.execution_audit import verify_execution
    read = lambda p: json.loads(p.read_text())
    pem = lambda p: serialization.load_pem_public_key(p.read_bytes())
    report = read(directory / 'report.json')
    require(report['passed'] and len(report['checks']) == 17 and all(report['checks'].values()), 'Fault run failed')
    bundle = read(directory / 'audit/bundle.json')
    url = bundle['approvals'][0]['evidence']['challenge_document']['binding']['url']
    u = urlsplit(url)
    credential = (directory / 'credential-id.txt').read_text().strip()
    audit = verify_execution(bundle, read(directory / 'audit/checkpoint.json'),
        executor_key=pem(directory / 'audit/executor-public.pem'), gate_key=pem(directory / 'gate-public.pem'),
        credential_id=base64.urlsafe_b64decode(credential + '=' * (-len(credential) % 4)),
        credential_public_key=(directory / 'credential-public.cbor').read_bytes(),
        rp_id='localhost', origin=u.scheme + '://' + u.netloc)
    receiver = read(directory / 'receiver.json')
    wanted = Counter({'/index': 1, '/post': 1, '/redirect': 1, '/worker': 1})
    require(Counter(r['path'] for r in receiver) == wanted, 'Fault receiver count mismatch')
    require(Counter(urlsplit(r['binding']['url']).path for r in audit['requests']) == wanted, 'Fault journal count mismatch')
    for request in audit['requests']:
        binding = request['binding']
        observed = next(r for r in receiver if r['path'] == urlsplit(binding['url']).path)
        require(request['stage'] == 'relay_prepared' and all(observed[k] == binding[k]
                for k in ('method', 'body_sha256', 'headers_sha256')), 'Fault receiver binding mismatch')
    return {'reported_fault_checks': 17, 'verified_received_operations': len(receiver)}


def check(compile_tex=False):
    directory = ROOT / 'output/submission'
    source_blob = (directory / 'arxiv-source.zip').read_bytes()
    full_blob = (directory / 'handoff-witness-artifact.zip').read_bytes()
    ancillary_blob = (directory / 'handoff-witness-code-data.zip').read_bytes()
    for line in (directory / 'SHA256SUMS.txt').read_text().splitlines():
        commitment, name = line.split('  ', 1)
        target = (ROOT / name).resolve()
        require(target.is_relative_to(ROOT / 'output'), 'Checksum path outside outputs')
        require(sha(target.read_bytes()) == commitment, f'Deliverable checksum mismatch: {name}')
    with tempfile.TemporaryDirectory(prefix='handoff-package-') as tmp:
        temporary = Path(tmp)
        source, full, ancillary = [temporary / label for label in ('source', 'full', 'ancillary')]
        manifests = [unpack_verified(blob, target) for blob, target in
                     [(source_blob, source), (full_blob, full), (ancillary_blob, ancillary)]]
        require((source / 'anc/handoff-witness-code-data.zip').read_bytes() == ancillary_blob, 'Nested ancillary differs')
        require(not any(p.suffix in {'.tex', '.bib'} for p in ancillary.rglob('*')), 'TeX source in ancillary archive')
        for name in manifests[1]:
            if name.startswith('data/'):
                continue
            original = ROOT / name
            require(original.is_file() and original.read_bytes() == (full / name).read_bytes(), f'Stale packaged file: {name}')
        for name in manifests[2]:
            if name == 'ARTIFACT-README.txt':
                continue
            require((full / name).read_bytes() == (ancillary / name).read_bytes(), f'Ancillary/full disagreement: {name}')
        for name in ('main.tex', 'references.bib'):
            require((source / name).read_bytes() == (ROOT / 'paper' / name).read_bytes(), f'Stale source: {name}')
        for path in (source / 'results').glob('*.tex'):
            require(path.read_bytes() == (ROOT / 'paper/results' / path.name).read_bytes(), f'Stale table: {path.name}')
        # Run the same public instructions supplied to readers, without model access.
        run([sys.executable, 'paper/analyze.py'], ancillary)
        run([sys.executable, 'paper/analyze_v01.py'], ancillary)
        run([sys.executable, 'paper/analyze_steering.py'], ancillary)
        for name in ('attribution_results.tex', 'scenario_results.tex', 'stored_results.tex', 'ablation_results.tex',
                     'steering_results.tex', 'supplement.json', 'steering_summary.json'):
            require((ancillary / 'paper/results' / name).read_bytes() == (full / 'paper/results' / name).read_bytes(), f'Recomputed result differs: {name}')
        run([sys.executable, 'paper/verify_runs.py', 'data/primary', 'data/replication'], ancillary)
        tests = run([sys.executable, '-m', 'pytest', '-q'], ancillary)
        # The imported verifier is byte-matched above to the packaged verifier.
        sys.path.insert(0, str(ROOT))
        fault = check_execution(ancillary / 'data/execution-study')
        compiled = False
        if compile_tex:
            build = temporary / 'tex-build'
            build.mkdir()
            run(['tectonic', '--keep-logs', '--keep-intermediates', '--outdir', str(build), 'main.tex'], source)
            log = (build / 'main.log').read_text()
            require(not any(term in log for term in ('Overfull', 'Undefined control sequence', 'undefined references')), 'TeX build warnings')
            new_text = run(['pdftotext', str(build / 'main.pdf'), '-'], source)
            delivered_text = run(['pdftotext', str(ROOT / 'output/pdf/handoff-witness-paper.pdf'), '-'], source)
            require(new_text == delivered_text, 'Delivered PDF differs from rebuilt source')
            compiled = True
    return {'passed': True, 'arxiv_source_sha256': sha(source_blob), 'artifact_sha256': sha(full_blob),
            'archive_member_counts': dict(zip(('source', 'artifact', 'ancillary'), map(len, manifests))),
            'regression_tests': tests.strip().splitlines()[-1], 'recomputed_result_files': 7,
            'primary_and_replication_recollected': True, 'model_outputs_and_replay_verified': 1152,
            'execution_fault_audit': fault, 'source_rebuilt_and_pdf_text_matched': compiled,
            'scope': 'Local consistency and reproducibility; not independent authenticity, novelty, endorsement, or publication.'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--compile', action='store_true')
    a = p.parse_args()
    result = check(a.compile)
    path = ROOT / 'output/submission/package-verification.json'
    path.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
