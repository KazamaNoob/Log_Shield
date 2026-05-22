import sqlite3
import os

def run_analytics_report():
    # Dynamically locate database file path relative to this script
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    db_path = os.path.join(base_dir, "data", "auth_tracker.db")

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
    except sqlite3.OperationalError as e:
        print(f"Database connection failed! Looked for database at: {db_path}")
        print(f"Error details: {e}")
        return

    print("=" * 45)
    print("       SIEM DAILY THREAT INTEL REPORT        ")
    print("=" * 45)

    # 1. Query 1: Calculate Total Failed Attacks (Look for integer 0)
    cursor.execute("SELECT COUNT(*) FROM auth_events WHERE event_type = 0")
    total_failures = cursor.fetchone()[0]  # Unpacked integer from tuple
    print(f"[*] Total Malicious Login Failures: {total_failures}")
    print("-" * 45)

    # 2. Query 2: Aggregate Top 5 Targeted Usernames (Look for integer 0)
    top_targets_query = """
        SELECT user_id, COUNT(*) as total 
        FROM auth_events 
        WHERE event_type = 0
        GROUP BY user_id 
        ORDER BY total DESC 
        LIMIT 5
    """
    cursor.execute(top_targets_query)
    top_accounts = cursor.fetchall()

    print("[*] Top 5 Most Targeted Account Usernames:")
    if not top_accounts:
        print("    No brute force logs recorded yet.")
    else:
        for index, row in enumerate(top_accounts, start=1):
            username = row[0]    # Extracted username from tuple row
            attack_count = row[1] # Extracted attack count from tuple row
            print(f"    {index}. Account: '{username}' -> Attacked {attack_count} times")

    print("=" * 45)

    conn.close()

if __name__ == "__main__":
    run_analytics_report()

