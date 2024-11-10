from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time 
import os 

from taskB_1 import taskB_packaged

class FileHandler(FileSystemEventHandler):
    def __init__(self, ignore_dirs, ignore_hidden, database_path):
        super().__init__()
        self.ignore_dirs = ignore_dirs
        self.ignore_hidden = ignore_hidden
        self.database_path = database_path

    def is_printable(self, event):
        if ( (self.ignore_hidden and os.path.basename(event.src_path).startswith('.')) or
            (self.ignore_dirs and event.is_directory) ):
            return False
        return True
    
    def handle_directory_change(self, event):
        if event.is_directory:
            print('searching...')
            # get path
            search_dir = event.src_path

            # search modified path for malware
            taskB_packaged(search_dir, self.database_path)        

    def on_created(self, event):
        if self.is_printable(event):
            print(f'Creation\t: {event.src_path}')
        self.handle_directory_change(event)

    def on_modified(self, event):
        if self.is_printable(event):
            print(f'Modification\t: {event.src_path}')
        self.handle_directory_change(event)

    def on_deleted(self, event):
        if self.is_printable(event):
            print(f'Deletion\t: {event.src_path}')
        self.handle_directory_change(event) # in case

def real_time_monitor_tool(search_directory, database_path):
    """ A real time monitor tool that searches for malware in a given directory.\n
    It reports any changes in the directory and searches for malware in the modified files

    Args:
        search_directory (str): A path to the directory to monitor for changes
        database_path (str): A path to the database file containing malware signatures
    """
    event_handler = FileHandler(ignore_dirs=False, ignore_hidden=False,
                                database_path=database_path)
    observer = Observer()
    observer.schedule(event_handler, path=search_directory, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":

    search_dir = 'taskB_1_files/level_0_dir_1'

    real_time_monitor_tool(search_dir, 'malware_signature.txt')