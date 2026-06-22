"""Create a Linux/Lambda-compatible zip (forward-slash paths, real folders)."""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path


def zip_directory(source_dir: Path, output_zip: Path) -> None:
    source_dir = source_dir.resolve()
    output_zip = output_zip.resolve()
    if output_zip.exists():
        output_zip.unlink()

    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(source_dir.rglob("*")):
            if path.is_dir():
                continue
            arcname = path.relative_to(source_dir).as_posix()
            zf.write(path, arcname)


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: python scripts/zip_for_lambda.py <package_dir> <output.zip>", file=sys.stderr)
        sys.exit(1)
    zip_directory(Path(sys.argv[1]), Path(sys.argv[2]))
    print(f"Created: {Path(sys.argv[2]).resolve()}")


if __name__ == "__main__":
    main()
