"""Prepare the static Pages artifact with the actual checked-out data revision."""
from pathlib import Path
import shutil
import subprocess


def build(root, revision, destination):
    destination.mkdir(parents=True, exist_ok=True)
    document = (root / 'index.html').read_text()
    if document.startswith('---\n'):
        document = document.split('\n---\n', 1)[1]
    document = document.replace('{{ site.github.build_revision }}', revision)
    (destination / 'index.html').write_text(document)
    for name in ['attacks.json', 'feed_status.json', 'skull-marker.png',
                 'decisions.json', 'backfill_progress.json']:
        if (root / name).exists():
            shutil.copy2(root / name, destination / name)


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    build(root, revision, root / '_site')
