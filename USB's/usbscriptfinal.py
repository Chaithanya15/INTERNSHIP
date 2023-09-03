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
import pandas as pd
import pywinusb.hid as hid
import hashlib

# Threading variables
threads = []
exit_flag = False
pause_flag = False
queue_lock = threading.Lock()
work_queue = queue.Queue()

# Config variables
has_quarantine = None
quarantine_folder = None
maxThreads = None
boxname = socket.gethostname()

# Known malicious file hashes (sample hashes for demonstration purposes)
KNOWN_MALICIOUS_HASHES = {
    "badfile.exe": "e99a18c428cb38d5f260853678922e03",  # MD5 hash of a known malicious file
    "virus.docx": "563dc687c81d19a7186309edebcd8c3d",   # MD5 hash of another known malicious file
}

class ScanThread(threading.Thread):
    """Scanning thread"""
    def __init__(self):
        threading.Thread.__init__(self)

    def scan(self, file):
        global infected_files, scanned, file_count, used
        try:
            # get file information
            file_name = os.path.basename(file)
            file_size = os.path.getsize(file)

            file_scan_start_time = time.time()

            # log the result
            log(
                f'Scan {file_name} '
                f'[{human_readable_size(file_size)}] '
                '-> '
                f'{status} ({(file_scan_end_time - file_scan_start_time):.1f}s)')
            logging.info(
                f'boxname="{boxname}", '
                f'file="{file_name}", '
                f'size="{file_size}", '
                f'status="{status}"", '
                f'duration="{int(file_scan_end_time - file_scan_start_time)}"')

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

    def real_scan(self, file):
        # Calculate the MD5 hash of the file
        md5_hash = hashlib.md5()
        with open(file, "rb") as f:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)

        file_hash = md5_hash.hexdigest()

        # Check if the file hash matches any of the known malicious file hashes
        if file_hash in KNOWN_MALICIOUS_HASHES.values():
            return "ALERT"
        else:
            return "CLEAN"

def config():
    global is_run_scan, has_quarantine, quarantine_folder, maxThreads
    """ read configuration file """
    # instantiate a ConfigParser
    config_parser = configparser.ConfigParser()
    # read the config file
    config_parser.read('config.ini')  # Updated configuration file name
    # set values
    is_run_scan = config_parser['DEFAULT']['RUN_SCAN'].lower() == "true"
    has_quarantine = config_parser['DEFAULT']['QUARANTINE'].lower() == "true"
    quarantine_folder = config_parser['DEFAULT']['QUARANTINE_FOLDER']
    # MaxThreads
    maxThreads = int(config_parser['DEFAULT']['THREADS'])

# -----------------------------------------------------------

def human_readable_size(size, decimal_places=1):
    """ Convert size to human readable string """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.{decimal_places}f}{unit}"
        size /= 1024.0
    return None

# -----------------------------------------------------------
# Print log
# -----------------------------------------------------------

def log(message, flush=False):
    """Print log message"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] {message}"
    print(log_message, flush=flush)

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

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

def resume_scanning():
    """
    Function to resume scanning when Ctrl+V is pressed.
    """
    global pause_flag
    pause_flag = False
    log("Scanning resumed.")

def get_usb_logs():
    usb_logs = []
    all_devices = hid.HidDeviceFilter().get_devices()

    for device in all_devices:
        # Get USB Manufacturer Name
        manufacturer_name = device.product_name

        usb_log = {
            "Date and Time(Plugin)": datetime.datetime.now(),
            "Date and Time(Plugout)": None,
            "Memory Size": None,
            "Make": device.vendor_name,
            "Vendor ID": hex(device.vendor_id),
            "Product ID": hex(device.product_id),
            "Manufacture": manufacturer_name,
            "Serial Number": device.serial_number,
        }
        usb_logs.append(usb_log)

    return usb_logs

def export_to_excel(usb_logs):
    df = pd.DataFrame(usb_logs)
    output_file = "usb_logs.xlsx"
    df.to_excel(output_file, index=False)
    print(f"USB logs saved to {output_file}")

def run_usb_log_analysis():
    """Execute the script for USB log analysis."""
    usb_logs = get_usb_logs()
    export_to_excel(usb_logs)

def main():
    try:
        global start_time, used, qfolder, scanned, file_count, infected_files

        log('AntiVirus Scanner - Windows-based Version', flush=True)

        # Load configuration
        config()

        # Create log file
        log_filename = 'current.log'  # Updated log file name
        logging.basicConfig(filename=log_filename, level=logging.INFO, format='%(asctime)s %(message)s')

        # Log start time
        start_time = time.time()

        # create scan threads
        for i in range(maxThreads):
            thread = ScanThread()
            thread.start()
            threads.append(thread)

        # Set up keyboard event handlers
        keyboard.add_hotkey('ctrl+c', signal_handler)
        keyboard.add_hotkey('ctrl+v', resume_scanning)

        while True:
            print("Choose the options:")
            print("1. Run USB log analysis")
            print("2. Scan Malware based on USB")
            print("3. Exit")

            try:
                option = int(input("Enter your choice (1, 2, or 3 to exit): "))
                if option == 1:
                    run_usb_log_analysis()
                elif option == 2:
                    log("Scanning not started. Start scan.")
                    main_scan()
                elif option == 3:
                    print("Exiting the script.")
                    sys.exit(0)
                else:
                    print("Invalid choice. Please enter 1, 2, or 3.")
            except ValueError:
                print("Invalid input. Please enter a valid number (1, 2, or 3).")

    except Exception as ex:
        log(f"Unexpected error: {str(ex)}", flush=True)
        logging.info(f'boxname="{boxname}", error="{str(ex)}"', exc_info=True)

def main_scan():
    global start_time, used, qfolder, scanned, file_count, infected_files

    # get list of drives
    drives = psutil.disk_partitions(all=False)

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
                queue_lock.acquire()
                work_queue.put(os.path.join(root, file))
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

if __name__ == "__main__":
    main()
    print("Choose the options:")
    print("1. Run USB log analysis")
    print("2. Scan Malware based on USB")
    print("3. Exit")

    try:
            option = int(input("Enter your choice (1, 2, or 3 to exit): "))
            if option == 1:
                run_usb_log_analysis()
            elif option == 2:
                main()
            elif option == 3:
                print("Exiting the script.")
                sys.exit(0)
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
    except ValueError:
            print("Invalid input. Please enter a valid number (1, 2, or 3).")
