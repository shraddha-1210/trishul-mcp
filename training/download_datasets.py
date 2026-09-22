"""Trishul Milestone 1 — Step 2: dataset acquisition.

Reproducible download of every M1 source into data/raw/. Idempotent: existing
targets are skipped unless --force is passed. This mirrors the interactive
acquisition performed during M1 and records the methods that actually worked:

  - MCPTox: 4open.science anonymized repo, whole-repo zip via its API.
  - GitHub sources: codeload.github.com release zips via HTTP (NO git clone, to
    honor the project's no-git rule and avoid nested .git repos).
  - HuggingFace: huggingface_hub.snapshot_download (uses the logged-in token).

Fail-loud: any download failure prints a clear error and is recorded; the script
does NOT substitute fallback datasets. See data/DATA_CARD.md for licenses and the
loud flags raised during acquisition.
"""
from __future__ import annotations

import argparse
import io
import sys
import zipfile
from pathlib import Path

import requests

RAW = Path(__file__).resolve().parents[1] / "data" / "raw"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36"}

MCPTOX_ID = "AAAI26-7C02"  # anonymous.4open.science repo id (arXiv:2508.14925)
GITHUB_SOURCES = {
    "mcpsecbench": "AIS2Lab/MCPSecBench",
    "mcp-safetybench": "xjzzzzzzzz/MCPSafety",
    "owasp-mcp-top10": "OWASP/www-project-mcp-top-10",
}
HF_DATASETS = {
    "prompt-injections": "deepset/prompt-injections",
    "jailbreak": "jackhhao/jailbreak-classification",
    "wildjailbreak": "allenai/wildjailbreak",  # gated: requires accepted license
}


def _log(msg: str) -> None:
    print(msg, flush=True)


def download_mcptox(force: bool = False) -> None:
    dest = RAW / "mcptox"
    if dest.exists() and not force:
        _log(f"skip  mcptox (exists at {dest})")
        return
    url = f"https://anonymous.4open.science/api/repo/{MCPTOX_ID}/zip"
    _log(f"get   mcptox <- {url}")
    r = requests.get(url, headers=UA, timeout=180)
    r.raise_for_status()
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        z.extractall(dest)
    for junk in dest.rglob(".DS_Store"):
        junk.unlink()
    _log(f"OK    mcptox -> {dest}")


def download_github(name: str, repo: str, force: bool = False) -> None:
    dest = RAW / name
    if dest.exists() and not force:
        _log(f"skip  {name} (exists at {dest})")
        return
    for branch in ("main", "master"):
        url = f"https://codeload.github.com/{repo}/zip/refs/heads/{branch}"
        r = requests.get(url, headers=UA, timeout=180)
        if r.status_code != 200:
            continue
        try:
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        except zipfile.BadZipFile:
            continue
        tmp = RAW / f"_tmp_{name}"
        zf.extractall(tmp)
        inner = next(tmp.iterdir())  # single top-level folder GitHub adds
        inner.rename(dest)
        tmp.rmdir()
        for junk in dest.rglob(".DS_Store"):
            junk.unlink()
        _log(f"OK    {name} <- {repo}@{branch} -> {dest}")
        return
    _log(f"FAIL  {name} <- {repo}: no reachable branch (tried main, master)")


def download_hf(name: str, repo_id: str, force: bool = False) -> None:
    from huggingface_hub import snapshot_download
    from huggingface_hub.utils import GatedRepoError, HfHubHTTPError

    dest = RAW / name
    if dest.exists() and not force:
        _log(f"skip  {name} (exists at {dest})")
        return
    try:
        snapshot_download(repo_id, repo_type="dataset", local_dir=str(dest))
        _log(f"OK    {name} <- {repo_id} -> {dest}")
    except (GatedRepoError, HfHubHTTPError) as e:
        _log(f"FAIL  {name} <- {repo_id}: gated/HTTP error: {str(e)[:200]}")
        _log("      -> accept the dataset license on its HuggingFace page while "
             "logged in with the active token, then re-run.")
    except Exception as e:  # fail loud, never silently substitute
        _log(f"FAIL  {name} <- {repo_id}: {type(e).__name__}: {str(e)[:200]}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Trishul M1 dataset acquisition")
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    ap.add_argument("--only", nargs="*", help="subset of dataset names to fetch")
    args = ap.parse_args()

    RAW.mkdir(parents=True, exist_ok=True)
    only = set(args.only) if args.only else None

    if only is None or "mcptox" in only:
        download_mcptox(args.force)
    for name, repo in GITHUB_SOURCES.items():
        if only is None or name in only:
            download_github(name, repo, args.force)
    for name, repo_id in HF_DATASETS.items():
        if only is None or name in only:
            download_hf(name, repo_id, args.force)
    _log("done. See data/DATA_CARD.md for licenses and flags.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
