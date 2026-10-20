#!/usr/bin/env python3
"""
ml/scripts/download_artifacts.py
--------------------------------
Fetch trained model artifacts into ml/artifacts/ instead of committing the
binaries to git.

Set ARTIFACTS_URL to a zip containing classifier.joblib + isolation_forest.joblib
(+ optional metrics.json), or pass --url. If you train locally with train.py you
do not need this — the artifacts are written directly.

Usage:
    ARTIFACTS_URL=https://example/artifacts.zip python ml/scripts/download_artifacts.py
    python ml/scripts/download_artifacts.py --url https://example/artifacts.zip
"""
import argparse
import io
import os
import sys
import urllib.request
import zipfile

ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "artifacts")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=os.environ.get("ARTIFACTS_URL", ""))
    args = parser.parse_args()

    if not args.url:
        print("No artifacts URL. Set ARTIFACTS_URL or pass --url, or train with "
              "`python ml/train.py`.")
        return 1

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    print(f"Downloading {args.url} ...")
    with urllib.request.urlopen(args.url) as resp:  # noqa: S310 (explicit user URL)
        data = resp.read()

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            zf.extractall(ARTIFACTS_DIR)
        print(f"Extracted artifacts to {ARTIFACTS_DIR}")
    except zipfile.BadZipFile:
        # Treat as a single joblib file.
        out = os.path.join(ARTIFACTS_DIR, "classifier.joblib")
        with open(out, "wb") as fh:
            fh.write(data)
        print(f"Saved {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
