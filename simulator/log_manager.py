# Allows Whiskers agent to save generated logs to a file for later parsing and analysis.
import os
from turtle import pd


def save_logs(args):
    """Allows Whiskers agent to save the current generated log under a differnt file name so it isnt overwritten in the next run.

    Args:
        filename (str): The name of the log file to save, e.g. "my_generated_log.log"
        directory (str): optional - The directory where logs should be saved. Default is ./data if not provided.
    """

    if len(args) > 2:
        print(
            "The 'save' command should be used alone with a filename and an optional alternative directory, e.g. 'save test.log' or 'save test.log ./alt_drectory test.log'"
        )
        return

    if len(args) == 2:
        filename = args[0]
        directory = args[1]

    if len(args) == 1:
        filename = args[0]
        directory = "data/"

    else:
        print("Something went wrong. Please check your command and try again.")
        return

    if not os.path.exists(directory):
        os.makedirs(directory)

    file_path = os.path.join(directory, filename)

    # Copy the current access log to the new destination
    with open("data/access.log", "r") as src, open(file_path, "w") as dst:
        dst.write(src.read())

    print(f"Agent Whiskers saved the log {file_path} with all the valuable cheese")


def log_shredder(args):
    """Allows Whiskers agent to delete a log file that is no longer needed.

    Args:
        filename (str): The name of the log file to delete, e.g. "my_generated_log.log"
        directory (str): The directory where logs are saved. Default is ./data if not provided.
    """

    if len(args) > 2:
        print(
            "The 'save' command should be used alone with a filename and an optional alternative directory, e.g. 'save test.log' or 'save test.log ./alt_drectory test.log'"
        )
        return

    if len(args) == 2:
        filename = args[0]
        directory = args[1]

    if len(args) == 1:
        filename = args[0]
        directory = "data/"

    else:
        print("Something went wrong. Please check your command and try again.")
        return

    file_path = os.path.join(directory, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        print(
            f"Agent Whiskers has shredded the file {file_path}. All evidence has been erased. The cheese is safe."
        )
    else:
        print(f"Log file {file_path} does not exist.")
