# Allows Whiskers agent to save generated logs to a file for later parsing and analysis.
import os
import shutil


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

    log_type = args[0].lower().strip()
    filename = args[1]
    directory = args[2] if len(args) == 3 else "data/"

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

    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = os.path.join(directory, filename)
    shutil.copyfile(source_path, file_path)

    print(f"Agent Whiskers saved the log {file_path} with all the valuable cheese")


def shred_logs(whiskers_agent, args):
    """Delete one configured log source file.

    Args:
        whiskers_agent: Active Whiskers instance holding configured log paths.
        args: [log_type, filename] or [log_type, filename, directory].
    """
    if len(args) == 0:
        print("No arguments provided. Check help info for guidance.")
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
            f"Agent Whiskers has shredded the file {source_path}. All evidence has been erased. The cheese is safe."
        )
    else:
        print(f"Log file {source_path} does not exist.")
