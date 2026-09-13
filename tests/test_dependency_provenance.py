"""Bind the metadata-only upstream repair without changing recovery authority."""
import hashlib
import importlib.metadata
import json

from packaging.requirements import Requirement


ARCHIVE = "https://codeload.github.com/Chia-Network/chia_puzzles/tar.gz/8ac1b8f794b6de159a74af334d562f71f4883798"
ARCHIVE_SHA256 = "b30f696398995845888f950d86351e203de534fec697a78710eec0758bf8ad64"
# Independently compared with the published PyPI 0.20.3 wheel, sha256
# cf55c342ec7827d244aea9f3d3e2fc7079807de6ab6c82d93c5d612c7f2ac1d2.
MODULES = {
    "__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "manage_clvm.py": "1f447b675da4e66d102197ec98b18fb137735ba5469e6bd4872d455dba97dedc",
    "programs.py": "d42000fb5b81e07b56301e61d9e775721712fea8c8eab316dabd4cde41cd2d2a",
    "tests/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "tests/test_import.py": "a032ff4d71a99a6fb7bfa4085c0ac1ec053620c5d939688a1bb765e3803464a0",
}


def test_upstream_archive_and_installed_python_bytes_are_pinned():
    dist = importlib.metadata.distribution("chia-puzzles-py")
    assert dist.version == "0.20.3"
    origin = json.loads(dist.read_text("direct_url.json"))
    assert origin["url"] == ARCHIVE
    assert origin["archive_info"]["hashes"]["sha256"] == ARCHIVE_SHA256
    files = {
        str(p).removeprefix("chia_puzzles_py/"): p
        for p in dist.files
        if str(p).startswith("chia_puzzles_py/") and str(p).endswith(".py")
    }
    assert set(files) == set(MODULES)
    for name, expected in MODULES.items():
        assert hashlib.sha256(dist.locate_file(files[name]).read_bytes()).hexdigest() == expected


def test_upstream_pytest_is_optional_and_patched_runner_is_selected():
    requirements = [Requirement(r) for r in importlib.metadata.requires("chia-puzzles-py")]
    runner = [r for r in requirements if r.name == "pytest"]
    assert len(runner) == 1
    assert runner[0].marker is not None
    assert not runner[0].marker.evaluate({"extra": ""})
    assert importlib.metadata.version("pytest") == "9.0.3"
