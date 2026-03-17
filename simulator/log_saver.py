# Allows Whiskers agent to save generated logs to a file for later parsing and analysis.
import os

def save_logs(filename, directory=None):
    """ Allows Whiskers agent to save the current generated log under a differnt file name so it isnt overwritten in the next run.
          
    Args:
        filename (str): The name of the log file to save, e.g. "my_generated_log.log"
        directory (str): optional - The directory where logs should be saved. Default is ./data if not provided.
    """

    if directory is None:
        directory = "data"

    if not os.path.exists(directory):
        os.makedirs(directory)

    destination = os.path.join(directory, filename)

    # Copy the current access log to the new destination
    with open("data/access.log", "r") as src, open(destination, "w") as dst:
        dst.write(src.read())

    print(f"Logs saved to {destination}")


def log_shredder(filename, directory=None):
    """Allows Whiskers agent to delete a log file that is no longer needed.
    
    Args:
        filename (str): The name of the log file to delete, e.g. "my_generated_log.log"
        directory (str): The directory where logs are saved. Default is ./data if not provided.
    """

    if directory is None:
        directory = "data"

    file_path = os.path.join(directory, filename)

    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Log file {file_path} has been deleted.")
    else:
        print(f"Log file {file_path} does not exist.")