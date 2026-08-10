"""
Git file and repo-level metadata utility.

Provides per-file last-commit information AND per-repo branch/name information
by querying the local git history of already-cloned repositories.  All calls
are cached (per process) so each file is only queried once even when the IG
builder visits many Java classes in the same repo.

Usage:
    from classes.git_utils import GitInfoCache
    cache = GitInfoCache()
    info  = cache.get(Path("/abs/path/to/MyClass.java"))
    # info = {
    #   "gitLastCommitId":      "abc1234def567890...",
    #   "gitLastCommitDate":    "2025-11-01T10:32:00+05:30",
    #   "gitLastCommitAuthor":  "jane.doe@example.com",
    #   "gitLastCommitMessage": "Fix NPE in CustomerProcessor",
    #   "gitRepoName":          "my-batch-service",    # from git remote origin URL
    #   "gitBranchName":        "main",                # from current HEAD
    # }

Design notes:
  - Uses subprocess (list form, not shell=True) to avoid shell-injection risk.
  - Falls back silently to empty strings if git is unavailable, the repo root
    cannot be located, or the file is not tracked.
  - `--follow` is used so renames/moves in history are handled correctly.
  - Repo-level info (branch name, repo name) is cached per repo root, not per
    file — all files in the same repo share those values.
"""

import subprocess
import logging
import re
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_EMPTY_FILE_INFO: Dict[str, str] = {
    "gitLastCommitId":      "",
    "gitLastCommitDate":    "",
    "gitLastCommitAuthor":  "",
    "gitLastCommitMessage": "",
}

_EMPTY_REPO_INFO: Dict[str, str] = {
    "gitRepoName":   "",
    "gitBranchName": "",
}

# Unit-separator character (never appears in git output fields)
_SEP = "\x1f"


def _find_repo_root(path: Path) -> Optional[Path]:
    """Walk up from *path* to find the nearest .git directory.

    Caps at 30 levels to avoid runaway loops on unusual mounts.
    Returns None if no .git directory is found.
    """
    current = path if path.is_dir() else path.parent
    for _ in range(30):
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _parse_repo_name_from_url(remote_url: str) -> str:
    """Extract the repository name from a git remote URL.

    Handles HTTPS, SSH (git@host:org/repo.git), and local paths.
    Returns empty string if the URL cannot be parsed.

    Examples:
        https://github.com/corp/my-batch-service.git → my-batch-service
        git@github.com:corp/my-batch-service.git     → my-batch-service
        /local/path/to/my-batch-service              → my-batch-service
    """
    url = remote_url.strip()
    # Strip trailing slashes and .git suffix
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    # Take the last path component
    name = re.split(r"[/:\\]", url)[-1]
    return name if name else ""


class GitInfoCache:
    """Per-process cache for git metadata of individual files and their repos.

    Returned dict contains six string keys:
        gitLastCommitId, gitLastCommitDate, gitLastCommitAuthor,
        gitLastCommitMessage   — per-file (from git log --follow)
        gitRepoName            — per-repo (from git remote get-url origin)
        gitBranchName          — per-repo (from git rev-parse --abbrev-ref HEAD)

    All values are empty strings when git info is unavailable.

    Usage — create one instance per IG builder run:
        git_cache = GitInfoCache()
        info = git_cache.get(Path(class_info.source_path))
    """

    def __init__(self):
        # file-level cache: absolute path str → {gitLastCommitId, ...}
        self._file_cache: Dict[str, Dict[str, str]] = {}
        # repo-level cache: repo root str → {gitRepoName, gitBranchName}
        self._repo_cache: Dict[str, Dict[str, str]] = {}

    def get(self, abs_file_path: Path) -> Dict[str, str]:
        """Return all six git metadata values for the given absolute file path.

        All values are empty strings when unavailable.
        """
        key = str(abs_file_path)
        if key not in self._file_cache:
            self._file_cache[key] = self._fetch_file(abs_file_path)

        file_info = self._file_cache[key]
        repo_root = _find_repo_root(abs_file_path)
        repo_info = self._get_repo_info(repo_root)

        return {**file_info, **repo_info}

    def _get_repo_info(self, repo_root: Optional[Path]) -> Dict[str, str]:
        """Return (cached) repo-level metadata for the given repo root."""
        if repo_root is None:
            return dict(_EMPTY_REPO_INFO)
        key = str(repo_root)
        if key not in self._repo_cache:
            self._repo_cache[key] = self._fetch_repo_level(repo_root)
        return self._repo_cache[key]

    # ------------------------------------------------------------------
    # Private fetchers
    # ------------------------------------------------------------------

    def _fetch_file(self, abs_file_path: Path) -> Dict[str, str]:
        """Run `git log --follow -1` for the file and parse output."""
        repo_root = _find_repo_root(abs_file_path)
        if repo_root is None:
            logger.debug("No .git root found for %s — skipping git log.", abs_file_path)
            return dict(_EMPTY_FILE_INFO)

        try:
            rel_path = abs_file_path.relative_to(repo_root)
        except ValueError:
            return dict(_EMPTY_FILE_INFO)

        fmt = f"%H{_SEP}%ae{_SEP}%aI{_SEP}%s"
        try:
            proc = subprocess.run(
                ["git", "log", "--follow", "-1", f"--format={fmt}", "--", str(rel_path)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            stdout = proc.stdout.strip()
            if not stdout:
                return dict(_EMPTY_FILE_INFO)

            parts = stdout.split(_SEP, 3)
            while len(parts) < 4:
                parts.append("")

            return {
                "gitLastCommitId":      parts[0].strip(),
                "gitLastCommitAuthor":  parts[1].strip(),
                "gitLastCommitDate":    parts[2].strip(),
                "gitLastCommitMessage": parts[3].strip(),
            }

        except FileNotFoundError:
            logger.debug("git not found on PATH; git metadata will be empty.")
            return dict(_EMPTY_FILE_INFO)
        except subprocess.TimeoutExpired:
            logger.warning("git log timed out for %s", abs_file_path)
            return dict(_EMPTY_FILE_INFO)
        except Exception as exc:
            logger.debug("git log failed for %s: %s", abs_file_path, exc)
            return dict(_EMPTY_FILE_INFO)

    def _fetch_repo_level(self, repo_root: Path) -> Dict[str, str]:
        """Fetch branch name (HEAD) and repo name (from remote URL) for a repo root."""
        result = dict(_EMPTY_REPO_INFO)
        cwd = str(repo_root)

        # Branch name
        try:
            proc = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=cwd, capture_output=True, text=True, timeout=10,
            )
            branch = proc.stdout.strip()
            if branch and branch != "HEAD":   # detached HEAD → keep empty
                result["gitBranchName"] = branch
        except Exception as exc:
            logger.debug("git rev-parse failed for %s: %s", repo_root, exc)

        # Repo name — try origin first, then any remote
        for remote in ("origin", "upstream"):
            try:
                proc = subprocess.run(
                    ["git", "remote", "get-url", remote],
                    cwd=cwd, capture_output=True, text=True, timeout=10,
                )
                if proc.returncode == 0:
                    name = _parse_repo_name_from_url(proc.stdout.strip())
                    if name:
                        result["gitRepoName"] = name
                        break
            except Exception:
                pass

        # If no remote found, fall back to directory name
        if not result["gitRepoName"]:
            result["gitRepoName"] = repo_root.name

        return result
