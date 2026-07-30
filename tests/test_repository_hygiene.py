"""Repository-level checks for accidental scratch artifacts."""
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_no_abandoned_root_scratch_scripts():
    forbidden = {
        "patch.py",
        "test_cuj.py",
        "test_cuj2.py",
    }
    present = sorted(name for name in forbidden if (ROOT / name).exists())
    assert present == [], f"Remove abandoned root scratch scripts: {present}"


def test_no_machine_specific_jules_verification_paths():
    marker = "/home/" + "jules/verification"
    matches: list[str] = []
    extensions = {".py", ".js", ".jsx", ".ts", ".tsx", ".kt", ".swift", ".sh", ".yml", ".yaml"}
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in extensions:
            continue
        if any(part in {".git", "node_modules", "dist", "build"} for part in path.parts):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if marker in text:
            matches.append(str(path.relative_to(ROOT)))
    assert matches == [], f"Remove machine-specific verification paths: {sorted(matches)}"
