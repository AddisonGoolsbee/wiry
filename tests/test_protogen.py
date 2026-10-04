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


def _protogen():
    import importlib.util

    spec = importlib.util.spec_from_file_location("protogen", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_an_enum_is_emitted_sorted_and_a_shared_table_by_name():
    pg = _protogen()
    fd = {"name": "type", "off": 0, "len": 8,
          "enum": {"8": "echo-request", "0": "echo-reply", "0x03": "dest-unreach"}}
    pg.validate_enum("x.toml", fd)
    assert pg.render_field(fd).endswith(
        '.named(&[(0, "echo-reply"), (3, "dest-unreach"), (8, "echo-request")]),'
    )
    fd = {"name": "code", "off": 0, "len": 16, "enum": "ETHER_TYPES"}
    pg.validate_enum("x.toml", fd)
    assert pg.render_field(fd).endswith(".host_named(crate::names::Host::EtherTypes),")


@pytest.mark.parametrize("fd, why", [
    ({"name": "t", "off": 0, "len": 4, "enum": {"16": "big"}}, "does not fit"),
    ({"name": "t", "off": 0, "len": 8, "enum": {"x": "nope"}}, "not an integer"),
    ({"name": "t", "off": 0, "len": 8, "enum": {"1": "a", "0x1": "b"}}, "twice"),
    ({"name": "t", "off": 0, "len": 8, "enum": "NO_SUCH"}, "shared table"),
    ({"name": "t", "off": 0, "len": 32, "kind": "ipv4", "enum": {"1": "a"}},
     "not an integer field"),
])
def test_a_malformed_enum_is_refused(fd, why):
    pg = _protogen()
    with pytest.raises(pg.SpecError, match=why):
        pg.validate_enum("x.toml", fd)


def _le(name, off, ln, at, n, kind="uint"):
    return {"name": name, "off": off, "len": ln, "kind": kind, "le": {"at": at, "len": n}}


def test_a_little_endian_group_is_emitted_on_every_field_in_it():
    pg = _protogen()
    fields = [_le("BC", 0, 2, 0, 2), _le("PB", 2, 2, 0, 2), _le("handle", 4, 12, 0, 2),
              {"name": "len", "off": 16, "len": 16, "kind": "le_uint"}]
    assert pg.validate_le("x.toml", fields) == [(0, 16), (16, 32)]
    assert pg.render_field(fields[2]).endswith(".little_endian(0, 2),")


@pytest.mark.parametrize("fields, why", [
    ([_le("a", 0, 8, 0, 9)], "2 to 8"),
    ([_le("a", 8, 16, 0, 2)], "outside its group"),
    ([_le("a", 0, 16, 0, 2), _le("b", 8, 16, 1, 2)], "overlap"),
    ([_le("a", 0, 8, 0, 2), {"name": "b", "off": 8, "len": 8}], "big-endian inside"),
    ([_le("a", 0, 48, 1, 6, "mac")], "exactly its own"),
    ([_le("a", 0, 32, 0, 4, "ipv4")], "cannot be little-endian"),
    ([dict(_le("a", 0, 16, 0, 2), kind="le_uint")], "already one group"),
])
def test_a_malformed_little_endian_group_is_refused(fields, why):
    pg = _protogen()
    with pytest.raises(pg.SpecError, match=why):
        pg.validate_le("x.toml", fields)


def test_a_selector_inside_a_little_endian_group_is_refused():
    pg = _protogen()
    with pytest.raises(pg.SpecError, match="little-endian group"):
        pg.refuse_le_overlap("x.toml", [(0, 16)], 8, 8, "[next]")
