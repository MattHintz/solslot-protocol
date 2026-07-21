from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_namespace.py"
RETIRED_BYTES = bytes((112, 111, 112, 117, 108, 105, 115))


def run_gate(*paths: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--paths", *(str(path) for path in paths)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_clean_material_passes(tmp_path: Path) -> None:
    clean = tmp_path / "release.txt"
    clean.write_text("solslot-v2")
    assert run_gate(clean).returncode == 0


def test_content_and_filename_are_rejected(tmp_path: Path) -> None:
    content = tmp_path / "content.txt"
    content.write_bytes(b"prefix-" + RETIRED_BYTES.upper() + b"-suffix")
    retired_path = tmp_path / ("old-" + RETIRED_BYTES.decode() + ".txt")
    retired_path.write_text("clean")
    assert run_gate(content).returncode == 1
    assert run_gate(retired_path).returncode == 1


def test_archive_member_is_rejected(tmp_path: Path) -> None:
    payload = tmp_path / "payload.txt"
    payload.write_bytes(RETIRED_BYTES)
    archive = tmp_path / "release.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(payload, arcname="assets/payload.txt")
    assert run_gate(archive).returncode == 1
