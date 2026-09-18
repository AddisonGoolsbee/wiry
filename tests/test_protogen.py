"""The generated layer tree must match its specs, so CI catches a hand edit to
a generated region and a spec change nobody regenerated alike."""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "dev" / "protogen" / "protogen.py"
SPECS = ROOT / "dev" / "protogen" / "specs"
LAYERS = ROOT / "crates" / "wiry-core" / "src" / "layers"

pytestmark = pytest.mark.skipif(
    not GEN.exists() or not SPECS.is_dir(), reason="protogen not present"
)


def specs():
    for p in sorted(SPECS.glob("*.toml")):
        with p.open("rb") as f:
            yield p, tomllib.load(f)


def test_regenerating_changes_nothing():
    r = subprocess.run(
        [sys.executable, str(GEN), "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr or r.stdout


def test_every_spec_cites_its_source():
    """The provenance rule, enforced rather than reviewed: a layout with no RFC
    or registry behind it does not ship."""
    for path, s in specs():
        assert s.get("citation", "").strip(), f"{path.name} has no citation"
        assert len(s["citation"]) > 40, f"{path.name}: citation is not a reference"


def test_proto_ids_are_unique_and_in_the_assigned_range():
    seen = {}
    for path, s in specs():
        n = s["num"]
        assert n not in seen, f"{path.name} reuses ProtoId {n} ({seen.get(n)})"
        seen[n] = path.name
        assert 32 <= n <= 111, f"{path.name}: ProtoId {n} outside 32..111"


def test_every_spec_has_a_module_and_every_module_has_a_spec():
    mods = {s.get("module", p.stem) for p, s in specs()}
    for m in mods:
        assert (LAYERS / f"{m}.rs").exists(), f"{m}.rs missing"
    declared = (LAYERS / "mod.rs").read_text()
    for m in mods:
        assert f"pub mod {m};" in declared, f"{m} not declared in layers/mod.rs"


def test_a_spec_without_a_citation_is_refused(tmp_path):
    bad = SPECS / "_pytest_tmp_nocite.toml"
    bad.write_text('name = "X"\nid = "X"\nnum = 110\nheader_len = 1\n'
                   '[[fields]]\nname = "a"\noff = 0\nlen = 8\n')
    try:
        r = subprocess.run(
            [sys.executable, str(GEN), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2
        assert "citation" in r.stderr
    finally:
        bad.unlink()


def test_hand_written_code_survives_regeneration_and_a_damaged_marker_stops_it():
    """The region is the only copy of what is inside it. Re-seeding over a
    half-present marker pair would delete a contributor's hook silently, so it
    has to raise instead."""
    path = LAYERS / "bfd.rs"
    before = path.read_text()
    try:
        path.write_text(
            before.replace(
                "// protogen:hand begin",
                "// protogen:hand begin\npub fn keep_me() -> u8 {\n    42\n}",
            )
        )
        r = subprocess.run([sys.executable, str(GEN)], cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert "keep_me" in path.read_text()

        path.write_text(path.read_text().replace("// protogen:hand end\n", ""))
        r = subprocess.run([sys.executable, str(GEN)], cwd=ROOT, capture_output=True, text=True)
        assert r.returncode == 2, "a damaged marker regenerated silently"
        assert "damaged" in r.stderr
        assert "keep_me" in path.read_text()
    finally:
        path.write_text(before)


def test_a_field_past_a_fixed_header_is_refused():
    """The flat model cannot place it, and a generator that guessed would be
    worse than one that stops."""
    bad = SPECS / "_pytest_tmp_toowide.toml"
    bad.write_text(
        'name = "X"\nid = "X"\nnum = 110\n'
        'citation = "A citation long enough to pass the length check in this test."\n'
        "header_len = 2\n"
        '[[fields]]\nname = "a"\noff = 0\nlen = 32\n'
    )
    try:
        r = subprocess.run(
            [sys.executable, str(GEN), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        assert r.returncode == 2
        assert "past the" in r.stderr
    finally:
        bad.unlink()
