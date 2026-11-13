from pathlib import Path

import pytest

from eaf.runner import find_tool

REPO = Path(__file__).resolve().parent.parent
SAMPLES = REPO / "samples"


def needs(*tools):
    missing = [t for t in tools if not find_tool(t)]
    return pytest.mark.skipif(bool(missing), reason=f"scanner(s) not installed: {missing}")


@pytest.fixture
def tree(tmp_path):
    """Build a small source tree from a {relative_path: content} dict."""
    def make(files: dict) -> Path:
        root = tmp_path / "src-under-test"
        for rel, content in files.items():
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return root
    return make
