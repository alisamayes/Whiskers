"""Filesystem boundary checks for Whiskers (path traversal prevention)."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any


class SecurityPathError(ValueError):
    """Raised when a user-supplied path would escape an allowed directory."""


def whiskers_root() -> Path:
    """Return the Whiskers project root directory.

    Args:
        None

    Returns:
        The directory containing the Whiskers package/module files.
    """
    return Path(__file__).resolve().parent


def whiskers_data_root(project_root: Path | None = None) -> Path:
    """Return the absolute ``<root>/data`` directory path."""
    root = (project_root or whiskers_root()).resolve()
    return (root / "data").resolve()


def ensure_under_directory(path: Path, allowed_root: Path, *, purpose: str) -> Path:
    """Resolve and require that ``path`` lies under ``allowed_root``.

    Returns the resolved path for convenience.
    """
    resolved = path.resolve()
    root = allowed_root.resolve()
    if resolved == root:
        raise SecurityPathError(f"{purpose}: path resolves to the directory itself.")
    if not resolved.is_relative_to(root):
        raise SecurityPathError(f"{purpose}: path must be under {root}.")
    return resolved


def safe_output_path_for_save(project_root: Path, args: list[str]) -> Path:
    """Resolve a safe destination path for the `save` command.

    Args:
        project_root: Whiskers project root directory.
        args: `save` arguments in one of these forms:
            - `[log_type, filename]`
            - `[log_type, filename, directory]`

    Returns:
        An absolute destination path for the saved output.

    Raises:
        SecurityPathError: If the resolved output path would escape `project_root`.
    """
    root = project_root.resolve()
    if len(args) == 2:
        second = args[1]
        p = Path(second)
        if p.is_absolute():
            return p.resolve()
        dest = (root / "data" / second).resolve()
        if not dest.is_relative_to(root):
            raise SecurityPathError("Relative save path escapes the Whiskers project root.")
        return dest

    if len(args) == 3:
        filename, directory = args[1], args[2]
        if not filename or Path(filename).name != filename:
            raise SecurityPathError("Filename must be a single component (no path separators).")
        if re.search(r"\.\.", directory) or re.search(r"\.\.", filename):
            raise SecurityPathError("Path segments must not contain '..'.")
        base = (root / directory).resolve()
        if not base.is_relative_to(root):
            raise SecurityPathError("Output directory escapes the Whiskers project root.")
        dest = (base / filename).resolve()
        if not dest.is_relative_to(base):
            raise SecurityPathError("Filename escapes the output directory.")
        if not dest.is_relative_to(root):
            raise SecurityPathError("Output path escapes the Whiskers project root.")
        return dest

    raise SecurityPathError("Invalid save arguments.")


def resolve_models_file(model_path: str, *, project_root: Path | None = None) -> Path:
    """Resolve a model path to an absolute path under `<root>/models`.

    Args:
        model_path: Model path string (absolute or relative).
        project_root: Optional project root override (defaults to `whiskers_root()`).

    Returns:
        The resolved absolute path for the model file.

    Raises:
        SecurityPathError: If the resolved path does not lie under `<root>/models`.
    """
    root = (project_root or whiskers_root()).resolve()
    models_root = (root / "models").resolve()
    p = Path(model_path)
    if p.is_absolute():
        resolved = p.resolve()
    else:
        resolved = (root / p).resolve()

    try:
        resolved.relative_to(models_root)
    except ValueError as exc:
        raise SecurityPathError(
            f"Model path must resolve under {models_root}: {model_path!r}"
        ) from exc

    return resolved


def read_expected_sha256(sha_path: Path) -> str:
    """Read a hex digest from a GNU-style `sha256sum` file.

    Args:
        sha_path: Path to the `.sha256` file.

    Returns:
        The expected SHA-256 digest as a 64-character lowercase hex string.
    """
    raw = sha_path.read_text(encoding="utf-8").strip().split()
    if not raw:
        raise ValueError(f"Empty hash file: {sha_path}")
    hex_part = raw[0].lower()
    if len(hex_part) != 64 or any(c not in "0123456789abcdef" for c in hex_part):
        raise ValueError(f"Invalid digest in {sha_path}")
    return hex_part


def verify_file_sha256(file_path: Path, expected_hex: str) -> bool:
    """Verify a file's SHA-256 digest matches the expected hex string.

    Args:
        file_path: Path to the file to hash.
        expected_hex: Expected SHA-256 hex digest.

    Returns:
        True if the computed digest matches `expected_hex`, otherwise False.
    """
    digest = hashlib.sha256(file_path.read_bytes()).hexdigest().lower()
    return digest == expected_hex.lower()


def secure_load_supervised_bundle(model_file: Path) -> Any:
    """Load a joblib bundle only if an adjacent SHA-256 file validates it.

    Args:
        model_file: Path to the `.joblib` model bundle.

    Returns:
        The loaded joblib object if integrity validation succeeds, otherwise None.
    """
    import joblib

    hash_path = model_file.with_name(model_file.name + ".sha256")
    if not hash_path.is_file():
        print(
            f"Supervised model not loaded: missing integrity file {hash_path}. "
            "Train with analysis.train_supervised_ip_classifier to generate it."
        )
        return None

    try:
        expected = read_expected_sha256(hash_path)
    except (OSError, ValueError) as e:
        print(f"Supervised model not loaded: could not read hash file ({e}).")
        return None

    if not verify_file_sha256(model_file, expected):
        print(
            f"Refusing to load supervised model: SHA-256 mismatch for {model_file}. "
            "Replace the file or regenerate with the training script."
        )
        return None

    return joblib.load(model_file)
