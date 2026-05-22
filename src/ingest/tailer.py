import os
import time

class Tailer:
    def __init__(self, file_path="/var/log/auth.log"):
        self.file_path = file_path
        self.current_inode = None
        self.file_handle = None
    def _get_inode(self):
        try:
            return os.stat(self.file_path).st_ino
        except FileNotFoundError:
            return None
    def follow(self):
        self.current_inode = self._get_inode()
        self.file_handle = open(self.file_path, 'r')
        self.file_handle.seek(0, os.SEEK_END)
        while True:
            line = self.file_handle.readline()
            if line:
                print(f"Captured: {line.strip()}"); yield line.strip()  # Print new lines as they are added
            else:
                time.sleep(0.1)  # Sleep briefly to avoid busy waiting
                new_inode = self._get_inode()
                if new_inode != self.current_inode:
                    # File has been rotated or replaced
                    self.file_handle.close()
                    self.current_inode = new_inode
                    self.file_handle = open(self.file_path, 'r')
                else:
                    continue
