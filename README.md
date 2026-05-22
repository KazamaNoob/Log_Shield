# LogShield: Real-Time SIEM & Intrusion Prevention System

LogShield is a high-performance Python-based Intrusion Prevention System (IPS) that monitors system authentication logs, detects distributed brute-force attacks using a multi-threaded evaluation engine, and automatically enforces permanent kernel-level firewall blocks using `ipset`.

## Features
- **Real-Time Log Ingestion**: Continuous monitoring of `/var/log/auth.log` via a high-performance tailer.
- **Asynchronous Database Pipeline**: Built-in batching system that offloads disk I/O operations to a background consumer thread.
- **Race-Condition Safety**: Utilizes thread locks to prevent duplicate firewall executions from concurrent network connections.
- **Self-Lockout Whitelisting**: Built-in intelligence to ignore local loopback traffic (`127.0.0.1`), keeping the host machine stable during heavy local tests.
- **Threat Analytics**: Standalone parsing tool to generate immediate metrics on top targeted accounts and total blocks.

## System Architecture Diagram
1. Ingestion Tier (`Tailer`) -> Parses live auth logs.
2. Worker Pipeline (`ThreadPoolExecutor`) -> Spawns threads to analyze anomalies.
3. Engine Core (`Process Event`) -> Tracks thresholds and checks IP Whitelists.
4. Mitigation Layer (`ipset`) -> Executes kernel-level bans on bad actors.
5. Storage Layer (`SQLite3`) -> Asynchronously batches log events to disk.

## How to Run
```bash
# Start the monitoring engine
sudo PYTHONPATH=src python3 src/main.py

# Generate a threat report in a separate terminal
python3 scripts/generate_report.py
```
