import os
import pwd
from datetime import datetime as dt
import time
from threading import Timer, Lock
from watchdog.observers import Observer # Observer monitors a file system and generates events based on it
from watchdog.events import FileSystemEventHandler # Handler with custom class that responds to the events

log_path = r"/home/felix/log_folder"
compromised_list = []
current_usr = os.environ.get('SUDO_USER') if os.environ.get("SUDO_USER") else pwd.getpwuid(os.getuid()).pw_name # prints current user of the session

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        self.delay = 0.1 # time delay
        self.timer = {}  # creates a dictionary to store TimerObject
    
    def debouncer(self, event, action):
        if event.src_path.endswith(("4913", "~")) or event.is_directory:
            return
        if event.src_path in self.timer:
            self.timer[event.src_path].cancel()
        
        def alert():    
            self.timer.pop(event.src_path, None)
            dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            with Lock():
                with open(os.path.join(log_path, "log.txt"), "a") as watchdog_log:
                    watchdog_log.write(f"File {action} by user {current_usr} {dt_now}, Path: {event.src_path}\n")

                print(f"File {action} by user {current_usr} {dt_now}, Path: {event.src_path}")

                if event.src_path not in compromised_list:
                    compromised_list.append(event.src_path)
                
                if os.path.exists(log_path):
                    with open(os.path.join(log_path, "log.txt"), "r") as watchdog_log:
                        lines = watchdog_log.readlines()

                with open(os.path.join(log_path, "log.txt"), "w") as watchdog_log:
                    for line in lines:
                        if not line.startswith("Compromised file:"):
                            watchdog_log.write(line)

                with open(os.path.join(log_path, "log.txt"), "a") as watchdog_log:
                    for file_path in compromised_list:
                        watchdog_log.write(f"Compromised file: {file_path}\n")
            
        self.timer[event.src_path] = Timer(self.delay, alert)
        self.timer[event.src_path].start()


    def on_modified(self, event): self.debouncer(event, "modified")

    def on_created(self, event): self.debouncer(event, "created")
    
    def on_deleted(self, event): self.debouncer(event, "deleted")

    def on_moved(self, event):
        if event.dest_path.endswith(("4913", "~")) or event.is_directory: return
        
        src_dir = os.path.dirname(event.src_path)
        dest_dir = os.path.dirname(event.dest_path)
        dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
        with Lock():
            with open(os.path.join(log_path, "log.txt"), "a") as watchdog_log:
                if src_dir == dest_dir:
                    watchdog_log.write(f"File renamed by user {current_usr} {dt_now}: {os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}\n")
                else:
                    watch_log.write(f"File moved by user {current_usr} {dt_now}: {event.src_path} -> {event.dest_path}\n")
                
            if event.dest_path not in compromised_list:
                compromised_list.append(event.dest_path)
                if event.src_path in compromised_list:
                    compromised_list.pop(compromised_list.index(event.src_path))
                
            if os.path.exists(log_path):
                with open(os.path.join(log_path, "log.txt"), "r") as watchdog_log:
                    lines = watchdog_log.readlines()

            with open(os.path.join(log_path, "log.txt"), "w") as watchdog_log:
                for line in lines:
                    if not line.startswith("Compromised file:"):
                        watchdog_log.write(line)

            with open(os.path.join(log_path, "log.txt"), "a") as watchdog_log:
                for file_path in compromised_list:
                    watchdog_log.write(f"Compromised file: {file_path}\n")

if __name__ == "__main__":
    handler = FIMHandler()
    path_to_watch = "/home/felix/important_files"
    observer = Observer()
    observer.schedule(handler, path_to_watch, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()