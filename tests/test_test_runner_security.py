"""Exercise the dependency boundary behind CVE-2025-71176 in owned fixtures."""
import os
import stat

import pytest
from _pytest import tmpdir


pytestmark = pytest.mark.skipif(
    not hasattr(os, "getuid") or os.stat not in os.supports_follow_symlinks,
    reason="POSIX symlink and ownership security boundary",
)


def factory(root, monkeypatch):
    monkeypatch.setenv("PYTEST_DEBUG_TEMPROOT", str(root))
    monkeypatch.setattr(tmpdir, "get_user", lambda: "solslot-security")
    return tmpdir.TempPathFactory(
        given_basetemp=None, retention_count=3, retention_policy="all",
        trace=lambda *args: None, _ispytest=True,
    )


@pytest.mark.parametrize("relative", [False, True])
def test_runner_rejects_symlink_temp_root_without_touching_target(tmp_path, monkeypatch, relative):
    target = tmp_path / "outside"
    target.mkdir(mode=0o755)
    target.chmod(0o755)
    sentinel = target / "sentinel"
    sentinel.write_text("unchanged")
    link = tmp_path / "pytest-of-solslot-security"
    link.symlink_to(target.name if relative else target, target_is_directory=True)
    with pytest.raises(OSError, match="symbolic link"):
        factory(tmp_path, monkeypatch).getbasetemp()
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert list(target.iterdir()) == [sentinel]
    assert sentinel.read_text() == "unchanged"


@pytest.mark.parametrize("existing_mode", [None, 0o700, 0o755])
def test_runner_preserves_legitimate_private_temp_directory(tmp_path, monkeypatch, existing_mode):
    root = tmp_path / "pytest-of-solslot-security"
    if existing_mode is not None:
        root.mkdir()
        root.chmod(existing_mode)
    base = factory(tmp_path, monkeypatch).getbasetemp()
    assert base.is_dir() and base.parent == root
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    (base / "normal-test.txt").write_text("works")
    assert (base / "normal-test.txt").read_text() == "works"
