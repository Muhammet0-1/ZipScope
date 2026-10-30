"""Create ONLY the two fixed, synthetic demo archives beside this script.

This helper writes files; ZipScope itself never writes inputs or outputs.
Existing demo archives are refused. It never reads a project directory.
"""
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parent
    for filename, names in [
        ("demo-match.zip", ["README.md", "LICENSE", "tool.py"]),
        ("demo-findings.zip", ["README.md", "tool.py", "debug.log"]),
    ]:
        with zipfile.ZipFile(root / filename, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in names:
                info = zipfile.ZipInfo(name, date_time=(2026, 10, 30, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, b"SYNTHETIC DEMO ONLY\n")


if __name__ == "__main__":
    main()
