# Allows Whiskers agent to save generated logs to a file for later parsing and analysis.
import os
import shutil
from pathlib import Path

from path_security import (
    SecurityPathError,
    ensure_under_directory,
    safe_output_path_for_save,
    whiskers_data_root,
    whiskers_root,
)


def _split_args_and_flags(args: list[str]) -> tuple[list[str], set[str]]:
    """Return (positional_args, flags) where flags are lowercase tokens like '--force'."""
    pos: list[str] = []
    flags: set[str] = set()
    for a in args:
        if isinstance(a, str) and a.startswith("--"):
            flags.add(a.strip().lower())
        else:
            pos.append(a)
    return pos, flags


def _is_interactive_repl(whiskers_agent) -> bool:
    return bool(getattr(whiskers_agent, "_interactive_repl", False))


def _require_confirm_or_force(
    whiskers_agent,
    prompt: str,
    *,
    force: bool,
) -> bool:
    """Require explicit confirmation in REPL, or `--force` when non-interactive."""
    if _is_interactive_repl(whiskers_agent):
        try:
            answer = input(f"{prompt} Type 'yes' to confirm: ").strip().lower()
        except EOFError:
            return False
        return answer == "yes"
    return force


def save_logs(whiskers_agent, args):
    """Save one configured log source under a different filename.

    Args:
        whiskers_agent: Active Whiskers instance holding configured log paths.
        args: [log_type, filename] or [log_type, filename, directory].
    """
    raw_args, flags = _split_args_and_flags(list(args))
    allow_absolute = "--allow-absolute" in flags
    overwrite = "--overwrite" in flags
    force = "--force" in flags or "--yes" in flags

    if len(raw_args) < 2 or len(raw_args) > 3:
        print(
            "Use: save [log_type] [filename] [directory(optional)] "
            "e.g. 'save access archived_access.log' or "
            "'save auth my_auth.log ./saved_logs'"
        )
        return

    log_type = raw_args[0].lower().strip()
    if not raw_args[1].strip():
        print("Filename or destination path is empty.")
        return

    source_attr = {
        "access": "access_logs",
        "auth": "auth_logs",
        "firewall": "firewall_logs",
    }.get(log_type)
    if source_attr is None:
        print("Invalid log type. Use one of: access, auth, firewall.")
        return

    sources = getattr(whiskers_agent, source_attr, None)
    if not sources:
        print(f"No configured {log_type} log source to save.")
        return
    source_path = sources[0].get("path", "").strip()
    if not source_path:
        print(f"{log_type} log source path is empty.")
        return

    root = whiskers_root()
    source_file = Path(source_path)
    if not source_file.is_absolute():
        source_file = (root / source_file).resolve()
    if not source_file.exists():
        print(f"Source log file does not exist: {source_file}")
        return

    data_root = whiskers_data_root(root)
    try:
        file_path = safe_output_path_for_save(root, raw_args)
    except SecurityPathError as e:
        print(f"Refusing save: {e}")
        return

    # Default hardening:
    # - refuse absolute destinations unless explicitly allowed
    # - refuse writing outside <root>/data unless explicitly allowed
    # - refuse overwriting existing files unless explicitly allowed
    try:
        dest_path = os.fspath(file_path)
    except TypeError:
        dest_path = str(file_path)

    is_abs = os.path.isabs(dest_path)
    under_data = True
    try:
        ensure_under_directory(file_path, data_root, purpose="Save destination")
    except SecurityPathError:
        under_data = False

    # Absolute paths are allowed if they still lie under <root>/data.
    if is_abs and not under_data and not allow_absolute:
        print(
            "Refusing save: absolute destination paths outside the Whiskers data directory "
            "are disabled by default. Use --allow-absolute to permit."
        )
        return

    if not under_data and not allow_absolute:
        print(
            f"Refusing save: destination must be under {data_root} by default. "
            "Use --allow-absolute to permit saving elsewhere."
        )
        return

    if os.path.exists(dest_path) and not overwrite:
        print(
            "Refusing save: destination file already exists. "
            "Use --overwrite to replace it."
        )
        return

    # For riskier operations (overwrite or saving outside data), require explicit confirmation
    # in REPL or --force when invoked via startup args / non-interactive paths.
    risky = os.path.exists(dest_path) or (is_abs or not under_data)
    if risky and not _require_confirm_or_force(
        whiskers_agent,
        "This save may overwrite a file or write outside the default data directory.",
        force=force,
    ):
        print("Save cancelled.")
        return

    try:
        parent = os.path.dirname(dest_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        shutil.copyfile(os.fspath(source_file), dest_path)
    except OSError as e:
        print(f"Save failed: {e}")
        return

    print(f"Agent Whiskers saved the log {file_path} with all the valuable cheese")


def shred_logs(whiskers_agent, args):
    """Delete one configured log source file.

    Args:
        whiskers_agent: Active Whiskers instance holding configured log paths.
        args: [log_type] or [log_type, ...] (see CLI / GUI); shred targets configured source path only.
    """
    raw_args, flags = _split_args_and_flags(list(args))
    force = "--force" in flags or "--yes" in flags
    allow_outside_data = "--allow-outside-data" in flags

    if len(raw_args) == 0:
        print("No arguments provided. Check help info for guidance.")
        return

    log_type = raw_args[0].lower().strip()
    source_attr = {
        "access": "access_logs",
        "auth": "auth_logs",
        "firewall": "firewall_logs",
    }.get(log_type)
    if source_attr is None:
        print("Invalid log type. Use one of: access, auth, firewall.")
        return

    sources = getattr(whiskers_agent, source_attr, None)
    if not sources:
        print(f"No configured {log_type} log source to shred.")
        return

    source_path = sources[0].get("path", "").strip()
    if not source_path:
        print(f"{log_type} log source path is empty.")
        return

    if not _require_confirm_or_force(
        whiskers_agent,
        "Permanently delete the configured log file for this type (cannot be undone).",
        force=force,
    ):
        print("Shred cancelled.")
        return

    root = whiskers_root()
    data_root = whiskers_data_root(root)
    source_file = Path(source_path)
    if not source_file.is_absolute():
        source_file = (root / source_file).resolve()
    if not source_file.exists():
        print(f"Log file {source_file} does not exist.")
        return

    try:
        resolved_source = ensure_under_directory(
            source_file,
            data_root,
            purpose="Shred target",
        )
    except SecurityPathError as e:
        if not allow_outside_data:
            print(
                f"Refusing shred: {e} "
                "(default boundary is <repo>/data; use --allow-outside-data to bypass)."
            )
            return
        resolved_source = source_file.resolve()

    try:
        os.remove(os.fspath(resolved_source))
    except OSError as e:
        print(f"Shred failed: {e}")
        return

    print(
        f"Agent Whiskers has shredded the file {resolved_source}. "
        "All evidence has been erased. The cheese is safe."
    )
