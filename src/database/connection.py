import sqlite3
from queue import Queue, Empty
from threading import Thread
from time import time


class DatabaseWriter:
    def __init__(self):
        self.log_queue = Queue()
        self.batch_limit = 100
        self.flush_interval = 3
        supv = Thread(target=self._database_consumer_loop, daemon=True)
        supv.start()

    def _database_consumer_loop(self):
        conn = sqlite3.connect("data/auth_tracker.db")
        conn.execute("CREATE TABLE IF NOT EXISTS auth_events (timestamp REAL, user_id TEXT, event_type TEXT)")
        curr_batch = []
        last_flush_time = time()
        while True:
            try:
                event = self.log_queue.get(timeout=1.0)
            except Empty:
                event = None
            if event:
                curr_batch.append((event.timestamp, event.user, event.status))
            if curr_batch and (len(curr_batch) >= self.batch_limit or time() - last_flush_time >= self.flush_interval):
                with conn:
                    conn.executemany(
                        "INSERT INTO auth_events (timestamp, user_id, event_type) VALUES (?, ?, ?)",
                        curr_batch
                    )
                curr_batch.clear()
                last_flush_time = time()

    def enqueue_log(self, event_obj):
        self.log_queue.put(event_obj)
