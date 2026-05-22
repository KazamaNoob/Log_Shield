# 1. Ingestion Tier Modules
from ingest.tailer import Tailer
from ingest.pre_filter import LogPreFilter

# 2. Data Model Module
from models.events import SSHAuditEvent

# 3. Core Detection & Mitigation Engines
from core.engine import Engine
from core.firewall import firewall  # Note: Use matching lowercase/uppercase name

# 4. Storage & Persistence Tier
from database.connection import DatabaseWriter

# 5. Support Utility Helpers
from utils.geoip import GeoIP
from utils.alerts import Alert
import re
from concurrent.futures import ThreadPoolExecutor
import time
import yaml
import threading  # Added for thread-safe block tracking

failed_ssh_regex = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<actor_ip>\S+)")
accepted_ssh_regex = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<actor_ip>\S+)")
sudo_regex = re.compile(r"sudo: (?P<user>\S+)\s+:\s+.*;\s* COMMAND=(?P<command>.+)$")

# Global tracking for mitigation safety
WHITELISTED_IPS = {"127.0.0.1", "::1"}
ALREADY_BLOCKED_IPS = set()
block_lock = threading.Lock()  # Prevents race conditions between worker threads

def main():
    try:
        with open("config/rules.yaml", "r") as f:
            config = yaml.safe_load(f)
        database_writer = DatabaseWriter()
        Firewall = firewall()
        alert = Alert(
            account=config["notification_policy"]["gmail_account"],
            password=config["notification_policy"]["gmail_app_password"],
        )
        engine = Engine(
            bf_window=config["brute_force_policy"]["window_seconds"],
            bf_threshold=config["brute_force_policy"]["failure_threshold"],
            max_users=config["behavioral_policy"]["max_unique_users_per_ip"],
        )
        pre_filter = LogPreFilter()
        tailer = Tailer()
        executor = ThreadPoolExecutor(max_workers=4)
        print("SIEM Core Initialized. Starting to monitor /var/log/auth.log...")
    except Exception as e:
        print(f"Initialization error: {e}")
        return
    print("SIEM Core Active... Tailing /var/log/auth.log")
    for raw_line in tailer.follow():
        if not pre_filter.is_interesting(raw_line):
            continue
        else:
            executor.submit(worker_pipeline, raw_line, engine, Firewall, alert, database_writer)

def worker_pipeline(raw_line, engine, Firewall, alert, database_writer):
    try:
        match1 = failed_ssh_regex.search(raw_line)
        match2 = accepted_ssh_regex.search(raw_line)
        match3 = sudo_regex.search(raw_line)
        if match1:
            user = match1.group("user")
            actor_ip = match1.group("actor_ip")
            event = SSHAuditEvent(timestamp=time.time(), actor_ip=actor_ip, user=user, status=False)
        elif match2:
            user = match2.group("user")
            actor_ip = match2.group("actor_ip")
            event = SSHAuditEvent(timestamp=time.time(), actor_ip=actor_ip, user=user,status=True)
        elif match3:
            user = match3.group("user")
            command = match3.group("command")
            event = SSHAuditEvent(timestamp=time.time(), actor_ip="127.0.0.1", user=user, status=True, command=command)
        else:
            return
        verdict = engine.process_event(event)
        if verdict:
            # Check whitelist and previous blocks with a thread-safe lock
            with block_lock:
                if event.actor_ip in WHITELISTED_IPS:
                    print(f"Mitigation skipped: IP {event.actor_ip} is whitelisted.")
                elif event.actor_ip in ALREADY_BLOCKED_IPS:
                    pass  # Prevent duplicate execution calls
                else:
                    ALREADY_BLOCKED_IPS.add(event.actor_ip)
                    Firewall.block_ip(event.actor_ip)
                    alert.send_alert(f"Blocked IP {event.actor_ip} for suspicious activity.")
                    
        database_writer.enqueue_log(event)
    except Exception as e:
        print(f"Error processing log line: {e}")

if __name__ == "__main__":
    main()

