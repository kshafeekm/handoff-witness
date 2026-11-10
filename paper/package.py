"""Build local arXiv source and reproducibility archives; never upload anything."""
import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'output/submission'
PDF = ROOT / 'output/pdf'


TABLES = ['attribution_results.tex', 'scenario_results.tex', 'stored_results.tex', 'ablation_results.tex', 'steering_results.tex']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_zip(path, files):
    manifest = {name: sha(data) for name, data in sorted(files.items())}
    entries = {**files, 'MANIFEST-SHA256.json': (json.dumps(manifest, indent=2) + '\n').encode()}
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(entries.items()):
            assert not name.startswith('/') and '..' not in Path(name).parts
            info = zipfile.ZipInfo(name, (2026, 11, 9, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, data)
    with zipfile.ZipFile(path) as archive:
        assert archive.testzip() is None


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    assert (PDF / 'main.pdf').is_file() and (PDF / 'main.bbl').is_file()
    source = (ROOT / 'paper/main.tex').read_text()
    log = (PDF / 'main.log').read_text()
    for bad in ['Undefined control sequence', 'There were undefined references', 'Overfull']:
        assert bad not in log, bad
    shutil.copyfile(PDF / 'main.pdf', PDF / 'handoff-witness-paper.pdf')
    files = {}
    for name in ['README.md', 'LICENSE', 'CITATION.cff', 'CONTRIBUTING.md', 'SECURITY.md',
                 'pyproject.toml', 'requirements-tested.txt',
                 'requirements-browser-tested.txt', 'requirements-model-tested.txt']:
        files[name] = (ROOT / name).read_bytes()
    for folder in ['handoff_witness', 'tests', 'docs', 'examples', 'paper']:
        for path in sorted((ROOT / folder).rglob('*')):
            if path.is_file() and path.suffix in {'.py', '.md', '.txt', '.json', '.tex', '.bib', '.html', '.js', '.css'}:
                if '__pycache__' not in path.parts:
                    files[str(path.relative_to(ROOT))] = path.read_bytes()
    permitted = {'capture.json', 'receiver.json', 'check.json', 'analysis.json', 'arms.json',
                 'events.jsonl', 'checkpoint.json', 'recorder-public.pem',
                 'manifest.json', 'rows.json', 'report.json'}
    for label, local in [('primary', 'attribution-v3-20261109'), ('replication', 'attribution-v3-20261110')]:
        run = ROOT / 'data' / label
        if not run.exists():
            run = ROOT / 'artifacts' / local
        assert run.is_dir()
        for path in sorted(run.rglob('*')):
            if path.is_file():
                assert path.name in permitted, path
                data = path.read_bytes()
                assert b'PRIVATE KEY-----' not in data
                files['data/' + label + '/' + str(path.relative_to(run))] = data
    # New studies contain public credentials and signed observations, never the
    # local approval database or model weights. Use explicit suffix/name bounds.
    for label, local in [('steering-v2', 'steering-v2-20261109'),
                         ('steering-browser-v2', 'steering-browser-v2-20261109'),
                         ('execution-study', 'execution-study-v2-20261109')]:
        run = ROOT / 'data' / label
        if not run.exists():
            run = ROOT / 'artifacts' / local
        assert run.is_dir()
        for path in sorted(run.rglob('*')):
            if path.is_file() and path.suffix in {'.json', '.jsonl', '.pem', '.cbor', '.txt', '.sha256'}:
                data = path.read_bytes()
                assert b'PRIVATE KEY-----' not in data
                files['data/' + label + '/' + str(path.relative_to(run))] = data
    artifact = OUT / 'handoff-witness-artifact.zip'
    write_zip(artifact, files)

    # arXiv asks that ancillary directories contain no TeX source. Include a
    # code/data ZIP without TeX/BibTeX; analyze.py regenerates its result tables.
    ancillary = {name: data for name, data in files.items()
                 if Path(name).suffix not in {'.tex', '.bib'} and name != 'paper/package.py'}
    ancillary['ARTIFACT-README.txt'] = (
        'Handoff Witness: synthetic data and source code\n\n'
        'Create a Python environment, then run:\n'
        'python -m pip install -r requirements-tested.txt -r requirements-browser-tested.txt -e .\n'
        'python paper/analyze.py\n'
        'python paper/analyze_v01.py\n'
        'python paper/analyze_steering.py\n'
        'python -m pytest -q\n'
        'python paper/verify_runs.py data/primary data/replication\n\n'
        'The manuscript and bibliography are outside this ancillary archive.\n'
        'analyze.py and analyze_v01.py regenerate the TeX result tables needed by the metric tests.\n'
        'Bundled signatures/keys prove consistency only, not independent authenticity.\n'
        'All browsing data are synthetic loopback fixtures; human labels and approvals are simulated.\n'
        'The steering pilot uses real local model outputs. Inference and browser replay are separate phases.\n'
        'Version 0.3.0. Compact results of v0.1 and v0.2 are under paper/results/v0.1 and paper/results/v0.2;\n'
        'their code is not distributed, so they can be recomputed but not re-collected.\n'
        'Software: MIT (LICENSE). Manuscript: CC BY 4.0 (paper/LICENSE.txt).\n'
    ).encode()
    ancillary_zip = OUT / 'handoff-witness-code-data.zip'
    write_zip(ancillary_zip, ancillary)
    tex = {'main.tex': source.encode(), 'references.bib': (ROOT / 'paper/references.bib').read_bytes(),
           'main.bbl': (PDF / 'main.bbl').read_bytes(),
           'anc/handoff-witness-code-data.zip': ancillary_zip.read_bytes()}
    for name in TABLES:
        tex['results/' + name] = (ROOT / 'paper/results' / name).read_bytes()
    write_zip(OUT / 'arxiv-source.zip', tex)

    abstract = re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}', source, re.S)[1]
    abstract = ' '.join(abstract.replace(r'\%', '%').split())
    title = re.search(r'\\title\{([^}]+)\}', source)[1].replace('\\\\', ' ').replace('--', '-')
    info = subprocess.check_output(['pdfinfo', str(PDF / 'main.pdf')], text=True)
    pages = re.search(r'Pages:\s+(\d+)', info)[1]
    tables = source.count('\\begin{table}') + sum((ROOT / 'paper/results' / n).read_text().count('\\begin{table}') for n in TABLES)
    metadata = (
        f'Title: {title}\nAuthors: Shafeek Kakkidumban Manayil\nAffiliation: Independent Researcher\n'
        'Primary category: cs.CR (Cryptography and Security)\n'
        'License: Creative Commons Attribution 4.0 International (CC BY 4.0)\n'
        f'Comments: {pages} pages, {tables} tables; version 0.3; code and experimental data included as ancillary material\n'
        'Journal reference: leave blank\nDOI: leave blank\nReport number: leave blank\n\n'
        f'Abstract:\n{abstract}\n\n'
        'Upload arxiv-source.zip as TeX source. It includes the code/data archive under anc/.\n'
        'Local build: Tectonic 0.17.0 (XeTeX/BibTeX); inspect the arXiv-generated preview.\n'
        'Repository: https://github.com/kshafeekm/handoff-witness\n'
        'No arXiv endorsement or announcement is implied by this package.\n'
        'Read the full manuscript before final submission. The title and claims are bounded\n'
        'to the controlled prototype study; no real-human attribution or novelty guarantee.\n'
    )
    (OUT / 'arxiv-metadata.txt').write_text(metadata)
    deliverables = [PDF / 'handoff-witness-paper.pdf', OUT / 'arxiv-source.zip', artifact,
                    ancillary_zip, OUT / 'arxiv-metadata.txt']
    (OUT / 'SHA256SUMS.txt').write_text(''.join(
        f'{sha(path.read_bytes())}  {path.relative_to(ROOT)}\n' for path in deliverables))
    print(json.dumps({str(p.relative_to(ROOT)): p.stat().st_size for p in deliverables}, indent=2))


if __name__ == '__main__':
    main()
