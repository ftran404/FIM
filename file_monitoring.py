import os
import pwd # provides access to the Unix user account and password database
from datetime import datetime as dt # import datetime class as the alias dt
import time
from threading import Timer, Lock # Timer implemented to delay the execution of functions, Lock to ensure that only one thread can access files at a time
from watchdog.observers import Observer # Observer monitors a file system and generates events based on it
from watchdog.events import FileSystemEventHandler # Handler with custom class that responds to the events

log_path = r"/home/felix/log_folder" # change this to your desired log path
os.makedirs(log_path, exist_ok=True) # creates any missing parents directories if they haven't already existed
compromised_list = []
current_usr = os.environ.get('SUDO_USER') if os.environ.get("SUDO_USER") else pwd.getpwuid(os.getuid()).pw_name # gets current user, if the script is run with sudo, gets the orginal user

class FIMHandler(FileSystemEventHandler): # creates a child class FIMHandler that inherits from FileSystemEventHandler
    def __init__(self):
        self.lock = Lock() # shared across functions so that they all have the same lock
        self.delay = 0.1 # time delay
        self.timer = {}  # creates a dictionary to store TimerObject
        self.is_paused = False
    
    def pause(self, bool):
        self.is_paused = bool
    
    def debouncer(self, event, action):
        if event.src_path.endswith(("4913", "~")) or event.is_directory: # avoids directory events and temp files created by vim
            return
        if event.src_path in self.timer: # if the file path is already in the timer dictionary
            self.timer[event.src_path].cancel() # cancels the existing timer for that file path
        
        def alert():    
            self.timer.pop(event.src_path, None) # removes the file path from the timer dictionary, with None as default value to avoid KeyError
            dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S") # displays the current dt in a nicely formatted way
            with self.lock: # implements Lock here to ensure only one thread can read and write to files at a time
  
                lines = []
                if os.path.exists(os.path.join(log_path, "log.txt")):
                    with open(os.path.join(log_path, "log.txt"), "r") as watchdog_log:
                        # returns a list of lines (only event logs)
                        lines = [line for line in watchdog_log if not line.startswith("Compromised file:")]
  
                # custom message we made here for better readability
                lines.append(f"File {action} by user {current_usr} {dt_now}, Path: {event.src_path}\n")
                
                # updates the list
                if event.src_path not in compromised_list:
                    compromised_list.append(event.src_path)
  
                with open(os.path.join(log_path, "log.txt"), "w") as watchdog_log:
                    # ensures event logs are written first, before the compromised list
                    watchdog_log.writelines(lines)
                    # writes the compromised list at the footer
                    for file_path in compromised_list:
                        watchdog_log.write(f"Compromised file: {file_path}\n")

        self.timer[event.src_path] = Timer(self.delay, alert) # sets the timer and calls the function alert() after the timer ends
        self.timer[event.src_path].start()


    def on_modified(self, event):
        if self.is_paused: # stops the event from passing if is_pause flag is True
            return
        else:    
            self.debouncer(event, "modified") # calls the function and specifies the correct action type

    def on_created(self, event): 
        if self.is_paused:
            return
        else:
            self.debouncer(event, "created")
    
    def on_deleted(self, event):
        if self.is_paused:
            return
        else:
            self.debouncer(event, "deleted")

    def on_moved(self, event):
        if self.is_paused:
            return
        else:    
            if event.dest_path.endswith(("4913", "~")) or event.is_directory: return
            
            src_dir = os.path.dirname(event.src_path) # source path
            dest_dir = os.path.dirname(event.dest_path) # destination path
            dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
            
            with self.lock:

                lines = []
                if os.path.exists(os.path.join(log_path, "log.txt")):
                    with open(os.path.join(log_path, "log.txt"), "r") as watchdog_log:
                        # returns a list of lines (only event logs)
                        lines = [line for line in watchdog_log if not line.startswith("Compromised file:")]
  
                # custom message we made here for better readability
                if src_dir == dest_dir: # if the file path didn't change then the file must've been renamed
                    lines.append(f"File renamed by user {current_usr} {dt_now}: {os.path.basename(event.src_path)} -> {os.path.basename(event.dest_path)}\n")
                else:
                    lines.append(f"File moved by user {current_usr} {dt_now}: {event.src_path} -> {event.dest_path}\n")
                
                # replaces the old file path in the compromised_list with the new file path
                if event.dest_path not in compromised_list:
                    compromised_list.append(event.dest_path)
                if event.src_path in compromised_list:
                    compromised_list.remove(event.src_path)
  
                with open(os.path.join(log_path, "log.txt"), "w") as watchdog_log:
                    # ensures event logs are written first, before the compromised list
                    watchdog_log.writelines(lines)
                    # writes the compromised list at the footer
                    for file_path in compromised_list:
                        watchdog_log.write(f"Compromised file: {file_path}\n")


if __name__ == "__main__":
    # Reload previously tracked compromised files back into memory on startup
    if os.path.exists(os.path.join(log_path, "log.txt")):
        with open(os.path.join(log_path, "log.txt"), "r") as watchdog_log:
            for line in watchdog_log:
                if line.startswith("Compromised file: "):
                    file_path = line.replace("Compromised file: ", "").strip()
                    if file_path not in compromised_list:
                        compromised_list.append(file_path)
                        
    import subprocess # allows Python to directly interact with our system's terminal
    import json # converts data to json-formatted strings
    handler = FIMHandler()
    path_to_watch = "/home/felix/important_files" # specify the path you want it to monitor here
    observer = Observer()
    observer.schedule(handler, path_to_watch, recursive=True) # by setting recursive to True, the watchdog will also monitor any folder within the main folder
    observer.start()

    try:
        while True:
            time.sleep(1)
            try:
                uuid = subprocess.run(['lsblk', '-o', 'name,uuid', '--json'], capture_output=True, check=True, text=True) # list all the drives by its name and uuid in the json format

                data = json.loads(uuid.stdout) # converts the output result of the command run above into Python dictionaries and lists
                block_devices = data.get('blockdevices', []) # gets all the items from blockdevices and puts them in a list

                uuid_list = [] # creates another list to store only the uuids

                for device in block_devices: # searches for each drive
                    for child in device.get('children', []): # looks through the keys in the children dictionary
                        if child.get('uuid'): # checks if there is a value assigned to the key 'uuid'
                            uuid_list.append(child['uuid'])

                myUSB_uuid = <Input your own UUID here> # this is the admin USB's uuid
                usb_connected = myUSB_uuid in uuid_list # True if the right USB's uuid is in the list otherwise, False
                if usb_connected and not handler.is_paused:
                    print("Special USB is plugged in. Deactivating watchdog")
                    handler.pause(True) # calls pause() subclass with the argument 'True'
                
                elif not usb_connected and handler.is_paused:
                    handler.pause(False) # calls pause() subclass with the argument 'False'            
            
            except subprocess.CalledProcessError as e:
                with open(os.path.join(log_path, "system_errors.log"), "a") as error_log:
                    dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
                    error_log.write(f"[{dt_now}] lsblk failed: {e}\n")
                continue # skips the rest of this while loop iteration

            except json.JSONDecodeError as e:
                with open(os.path.join(log_path, "system_errors.log"), "a") as error_log:
                    dt_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
                    error_log.write(f"[{dt_now}] Failed to parse lsblk JSON output: {e}\n")
                continue # skips the rest of this loop iteration

    except KeyboardInterrupt: # catches when the user Ctrl+C out of the program
        observer.stop() # signals for the background thread to stop
    observer.join() # waits for the backgroud thread to fully terminate before completely shutting down the program
