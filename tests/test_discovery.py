import os

from eaf.discovery import discover, is_test_file, parse_requirements, tree_digest


def test_detects_languages_manifests_frameworks_and_build_systems(tree):
    root = tree({
        "app/main.py": "print('x')\n",
        "src/a.c": "int main(void){return 0;}\n",
        "src/a.hpp": "#pragma once\n",
        "web/index.ts": "export const a = 1;\n",
        "web/util.js": "module.exports = {};\n",
        "tools/Thing.java": "class Thing {}\n",
        "requirements.txt": "flask==2.0.0\nrequests>=2\n",
        "web/package.json": '{"dependencies": {"react": "18.0.0"}, "scripts": {"build": "tsc"}}',
        "CMakeLists.txt": "find_package(Boost REQUIRED)\n",
        "node_modules/x/index.js": "ignored\n",
        "build/out.py": "ignored\n",
    })
    inv = discover(root)
    assert set(inv.languages) == {"python", "c", "cpp", "typescript", "javascript", "java"}
    assert inv.supported_languages == ["c", "cpp", "javascript", "python", "typescript"]
    assert inv.unsupported_languages == ["java"]
    assert {m["path"] for m in inv.manifests} == {"requirements.txt", "web/package.json"}
    assert {f["name"] for f in inv.frameworks} == {"Flask", "requests", "React", "Boost"}
    systems = {b["system"] for b in inv.build_systems}
    assert {"cmake", "npm-scripts"} <= systems
    assert "node_modules/" in inv.excluded and "build/" in inv.excluded
    assert not any(f.rel.startswith(("node_modules", "build")) for f in inv.files)


def test_profile_excludes_and_symlinks_are_not_followed(tree, tmp_path):
    root = tree({"a.py": "x = 1\n", "third_party/lib.py": "y = 2\n"})
    outside = tmp_path / "outside.py"
    outside.write_text("secret = 1\n")
    os.symlink(outside, root / "link.py")
    inv = discover(root, ["third_party/*"])
    assert [f.rel for f in inv.files] == ["a.py"]
    assert inv.skipped_symlinks == 1


def test_parse_requirements_pinning():
    reqs = parse_requirements("# c\nflask==2.0.0\nrequests>=2 ; python_version>'3'\n-r other.txt\n"
                              "uvicorn[standard]==0.30.0\nblack\n")
    assert [(r["name"], r["pinned"]) for r in reqs] == [
        ("flask", True), ("requests", False), ("uvicorn", True), ("black", False)]


def test_is_test_file():
    assert is_test_file("tests/test_x.py")
    assert is_test_file("src/foo.test.ts")
    assert is_test_file("pkg/thing_test.cpp")
    assert not is_test_file("src/contest.py")


def test_tree_digest_changes_with_content(tree):
    root = tree({"a.py": "x = 1\n"})
    d1 = tree_digest(root, discover(root).files)
    assert d1 == tree_digest(root, discover(root).files)
    (root / "a.py").write_text("x = 2\n")
    assert d1 != tree_digest(root, discover(root).files)
