import os
import sys
import time
import hashlib
import psutil
import shutil
import socket
import platform
import subprocess
from collections import defaultdict
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Define quarantine directory path
QUARANTINE_DIR = '/path/to/quarantine'

# Define a list of process that should be running in the system
WHITELISTED_PROCESSES = ["explorer.exe","chrome.exe","notepad.exe"]

class RansomwareDetectorHandler(FileSystemEventHandler):
    def __init__(self):
        #initialize whitelisted_files set
        self.whitelisted_files = set()
        self.process_files = defaultdict(set)
        self.observed_files = set()
        self.extensions_to_observe = set()
        self.hostname = socket.gethostname()
        self.os_info = platform.system()
        
    def on_modified(self, event):
        # ignore changes to whitelisted files
        if event.src_path in self.whitelisted_files:
            return
        
        # Get file hash
        file_hash = self.get_file_hash(event.src_path)
        #Check if file is whitelisted
        if not self.is_file_whitelisted(file_hash):
            print("Ransomware detected!")
            # Move the affected files to quarantine directory
            if not os.path.exists(QUARANTINE_DIR):
                os.makedirs(QUARANTINE_DIR)
            shutil.move(event.src_path, QUARANTINE_DIR)
            #Stop the process responsible for the encryption
            process_name = self.get_file_process(event.src_path)
            if process_name not in WHITELISTED_PROCESSES:
                os.system("taskkill /f /im "+ process_name+ ".exe")
            #Disconnect the system from the network
            os.system("netsh interface set interface 'Ethernet' admin=disable")
            #Alert the user
            os.system("msg * Ransomware detected!")
            self.send_email_alert(event.src_path)
            self.syslog_alert(event.src_path)
            #Restore the files from a backup
            shutil.copy2('/path/to/backup'+ event.src_path, event.src_path)
    
    def on_created(self, event):
        if self.is_file_whitelisted(self.get_file_hash(event.src_path)):
            self.whitelisted_files.add(event.src_path)
        else:
            process_name = self.get_file_process(event.src_path)
