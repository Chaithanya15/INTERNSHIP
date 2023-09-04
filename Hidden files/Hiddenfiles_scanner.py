import configparser
import os
import shutil
import socket
import sys
import time
import threading
import psutil
import queue
import logging
import datetime
from pathlib import Path
import signal
import keyboard

# -----------------------------------------------------------
# Threading variables
# -----------------------------------------------------------

# Define the ScanThread class before the main function
class ScanThread(threading.Thread):
    """Scanning thread"""
    def __init__(self, search_hidden_only=False, extensions=None):
        threading.Thread.__init__(self)
        self.search_hidden_only = search_hidden_only
        self.extensions = extensions

    def run(self):
        while not exit_flag:
            queue_lock.acquire()
            if not work_queue.empty() and not pause_flag:
                file = work_queue.get()
                queue_lock.release()
                self.scan(file)
            else:
                queue_lock.release()
            time.sleep(0.1)

    def scan(self, file):
        global infected_files, scanned, file_count, used
        try:
            # get file information
            file_name = os.path.basename(file)
            file_size = os.path.getsize(file)

            # Check if the file is hidden
            if self.search_hidden_only and not is_hidden(file):
                return

            if self.extensions:
                file_ext = os.path.splitext(file)[1].lower()
                if not any(file_ext.endswith(ext.lower()) for ext in self.extensions):
                    return

            if is_run_scan:
                # Replace this section with your real antivirus scanning logic for Windows
                # For this example, we assume that the file is clean
                status = "CLEAN"
            else:
                # Simulate fake scan (assume the file is clean)
                status = "CLEAN"

            # log the result with full file path
            full_path = os.path.abspath(file)
            if self.search_hidden_only:
                log(f"Hidden files are found: Scan {full_path} [{human_readable_size(file_size)}]", file='hiddenfiles.log')
            else:
                log(f"All files are found: Scan {full_path} [{human_readable_size(file_size)}]", file='allfiles.log')

            # Log extension-specific result
            if self.extensions:
                log(f"Scan {full_path} [{human_readable_size(file_size)}]", file='extensionfiles.log')

            # Get lock
            queue_lock.acquire()

            scanned += file_size
            file_count += 1

            if status == "ALERT":
                # add file to list
                infected_files.append(file)

            # Release lock
            queue_lock.release()

            if has_quarantine and status == "ALERT":
                if not os.path.isdir(quarantine_folder):
                    os.makedirs(quarantine_folder)
                shutil.copyfile(file, os.path.join(quarantine_folder, file_name))

        except Exception as ex:
            log(f"Unexpected error: {str(ex)}", flush=True)
            logging.info(
                f'boxname="{boxname}", '
                f'error="{str(ex)}"', exc_info=True)

# Config variables
is_run_scan = None
has_quarantine = None
quarantine_folder = None
maxThreads = None
boxname = socket.gethostname()

# Threading variables
threads = []
exit_flag = False
pause_flag = False
queue_lock = threading.Lock()
work_queue = queue.Queue()

# -----------------------------------------------------------

def log(message, flush=False, file=None):
    """Print log message"""
    if file:
        with open(file, 'a') as f:
            f.write(f"{message}\n")
    print(message, flush=flush)

def is_hidden(filepath):
    """Check if the file or directory is hidden"""
    if os.name == 'nt':
        try:
            attrs = os.stat(filepath).st_file_attributes
            return attrs & 2 != 0
        except OSError:
            pass
    else:
        return os.path.basename(filepath).startswith('.')

    return False

# Rest of the code remains the same...

def config():
    global is_run_scan, has_quarantine, quarantine_folder, maxThreads
    """ read configuration file """
    # instantiate a ConfigParser
    config_parser = configparser.ConfigParser()
    try:
        # read the config file
        config_parser.read('config.ini')  # Updated configuration file name

        # set values with defaults if not found in the config
        is_run_scan = config_parser.getboolean('DEFAULT', 'RUN_SCAN', fallback=True)
        has_quarantine = config_parser.getboolean('DEFAULT', 'QUARANTINE', fallback=False)
        quarantine_folder = config_parser.get('DEFAULT', 'QUARANTINE_FOLDER', fallback='quarantine')
        # MaxThreads
        maxThreads = int(config_parser.get('DEFAULT', 'THREADS', fallback='4'))
    except Exception as ex:
        log(f"Error reading configuration: {str(ex)}", flush=True)
        is_run_scan = True
        has_quarantine = False
        quarantine_folder = 'quarantine'
        maxThreads = 4

# Rest of the code remains the same...


def signal_handler(sig, frame):
    """
    Signal handler for Ctrl+C (SIGINT).
    Stops the scanning threads and exits the program gracefully.
    """
    global exit_flag
    exit_flag = True

    for thread in threads:
        thread.join()

    log("Scan stopped by user (Ctrl+C).")
    logging.info('Scan stopped by user (Ctrl+C).')
    sys.exit(0)

def resume_scanning():
    """
    Function to resume scanning when Ctrl+V is pressed.
    """
    global pause_flag
    pause_flag = False
    log("Scanning resumed.")

def human_readable_size(size, decimal_places=1):
    """ Convert size to human readable string """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.{decimal_places}f}{unit}"
        size /= 1024.0
    return None

def main():
    try:
        global start_time, used, qfolder, scanned, file_count, infected_files

        log('Searching for Hidden files:', flush=True)
        log('Options:')
        log('1. Search only Hidden files')
        log('2. Search All files')
        log('3. Search for Hidden files based on .Extension (Multiple extensions supported)')

        choice = input("Enter the option number: ")

        if choice not in ["1", "2", "3"]:
            log("Invalid option. Please select either 1, 2, or 3.")
            return

        search_hidden_only = choice == "1"

        extensions = []
        if choice == "3":
            extensions_input = input("Enter input for .Extension (Ex: .exe, .txt): ")
            extensions = [ext.strip() for ext in extensions_input.split(",")]
            extension_log_file = "extensionfiles.log"
            if os.path.exists(extension_log_file):
                os.remove(extension_log_file)

        if search_hidden_only:
            log('Hidden files are found:', file='hiddenfiles.log')
        else:
            # Do not use allfiles.log when option 3 is chosen
            if choice != "3":
                log('All files are found:', file='allfiles.log')

        log('Scanning - Windows-based Version', flush=True)

        # Load configuration
        config()

        # Create log files
        hidden_files_log = 'hiddenfiles.log'
        if os.path.exists(hidden_files_log):
            os.remove(hidden_files_log)

        # Do not use allfiles.log when option 3 is chosen
        if choice != "3":
            all_files_log = 'allfiles.log'
            if os.path.exists(all_files_log):
                os.remove(all_files_log)

            logging.basicConfig(filename=all_files_log, level=logging.INFO, format='%(asctime)s %(message)s')

        # Log start time
        start_time = time.time()

        # create scan threads
        for i in range(maxThreads):
            thread = ScanThread(search_hidden_only=search_hidden_only, extensions=extensions if choice == "3" else None)
            thread.start()
            threads.append(thread)

        # Set up keyboard event handlers
        keyboard.add_hotkey('ctrl+c', signal_handler)
        keyboard.add_hotkey('ctrl+v', resume_scanning)

        # get list of drives
        drives = psutil.disk_partitions(all=True)

        # log device information
        for drive in drives:
            log(f"Scanning {drive.mountpoint}...")
            used = psutil.disk_usage(drive.mountpoint).used

            # get folder to quarantine
            if has_quarantine:
                qfolder = os.path.join(drive.mountpoint, quarantine_folder)

            scanned = 0
            file_count = 0
            infected_files = []

            # start scanning
            for root, _, files in os.walk(drive.mountpoint):
                for file in files:
                    full_path = os.path.join(root, file)

                    # Filter based on user choice (hidden files, all files, or specific extensions)
                    if (search_hidden_only and is_hidden(full_path)) or (not search_hidden_only):
                        if choice == "3" and not any(full_path.lower().endswith(ext.lower()) for ext in extensions):
                            continue

                        queue_lock.acquire()
                        work_queue.put(full_path)
                        queue_lock.release()

        # wait for all threads to complete
        while not work_queue.empty():
            pass

        # notify threads it's time to exit
        global exit_flag
        exit_flag = True

        # wait for all threads to complete
        for thread in threads:
            thread.join()

        # Print summary
        log(f"Scanned files: {file_count}", flush=True)
        log(f"Infected files: {len(infected_files)}", flush=True)
        log(f"Elapsed time: {str(datetime.timedelta(seconds=int(time.time() - start_time)))}", flush=True)

        log("Scan completed.")
        logging.info('Scan completed.')
    except Exception as ex:
        log(f"Unexpected error: {str(ex)}", flush=True)
        logging.info(f'boxname="{boxname}", error="{str(ex)}"', exc_info=True)

if __name__ == "__main__":
    main()
