import os
import pwd
from datetime import datetime as dt
import time
from threading import Timer
from watchdog.observers import Observer # Observer monitors a file system and generates events based on it
from watchdog.events import FileSystemEventHandler

log_path = r"/home/felix/log_folder"

class FIMHandler(FileSystemEventHandler):
    def __init__(self):
        self.delay = 0.1
        self.timer = {}
    
    def debouncer(self, event, action):
        if event.src_path.endswith(("4913", "~")) or event.is_directory:
            return
        if (event.src_path, action) in self.timer:
            self.timer[event.src_path].cancel()
        
        def alert():    
            self.timer.pop(event.src_path, None)
            
            current_usr = os.environ.get('SUDO_USER') if os.environ.get("SUDO_USER") else pwd.getpwuid(os.getuid()).pw_name # prints user of the current session
            dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(os.path.join(log_path, "log.txt"), "a") as watchdog_log:
                watchdog_log.write(f"File {action} by user {current_usr} {dt_now}, Path: {event.src_path}\n")
            print(f"File {action} by user {current_usr} {dt_now}, Path: {event.src_path}")
        self.timer[event.src_path] = Timer(self.delay, alert)
        self.timer[event.src_path].start()

    def on_modified(self, event: FileSystemEvent) -> None:
        self.debouncer(event, "modified")

    def on_created(self, event: FileSystemEvent) -> None:
        self.debouncer(event, "created")
    
    def on_deleted(self, event: FileSystemEvent) -> None:
        self.debouncer(event, "deleted")

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