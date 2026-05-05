# Allows Whiskers agent to save generated logs to a file for later parsing and analysis.
import os
import shutil

from path_security import SecurityPathError, safe_output_path_for_save, whiskers_root


def _interactive_confirm(whiskers_agent, prompt: str) -> bool:
    """Require explicit ``yes`` in the REPL for file operations (finding 7 mitigation)."""
    if not getattr(whiskers_agent, "_interactive_repl", False):
        return True
    try:
        answer = input(f"{prompt} Type 'yes' to confirm: ").strip().lower()
    except EOFError:
        return False
    return answer == "yes"


def save_logs(whiskers_agent, args):
    """Save one configured log source under a different filename.

    Args:
        whiskers_agent: Active Whiskers instance holding configured log paths.
        args: [log_type, filename] or [log_type, filename, directory].
    """
    if len(args) < 2 or len(args) > 3:
        print(
            "Use: save [log_type] [filename] [directory(optional)] "
            "e.g. 'save access archived_access.log' or "
            "'save auth my_auth.log ./saved_logs'"
        )
        return

    if not _interactive_confirm(
        whiskers_agent,
        "Save a copy of the configured log (possible overwrite at destination).",
    ):
        print("Save cancelled.")
        return

    log_type = args[0].lower().strip()
    if not args[1].strip():
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
    if not os.path.exists(source_path):
        print(f"Source log file does not exist: {source_path}")
        return

    root = whiskers_root()
    try:
        file_path = safe_output_path_for_save(root, args)
    except SecurityPathError as e:
        print(f"Refusing save: {e}")
        return

    try:
        parent = os.path.dirname(file_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        shutil.copyfile(source_path, file_path)
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
    if len(args) == 0:
        print("No arguments provided. Check help info for guidance.")
        return

    if not _interactive_confirm(
        whiskers_agent,
        "Permanently delete the configured log file for this type (cannot be undone).",
    ):
        print("Shred cancelled.")
        return

    log_type = args[0].lower().strip()
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

    if os.path.exists(source_path):
        os.remove(source_path)
        print(
            f"Agent Whiskers has shredded the file {source_path}. "
            "All evidence has been erased. The cheese is safe."
        )
    else:
        print(f"Log file {source_path} does not exist.")
