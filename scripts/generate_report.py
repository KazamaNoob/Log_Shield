import sqlite3


def run_analytics_report():
    # 1. Establish database connection handle
    conn = sqlite3.connect("data/auth_tracker.db")
    cursor = conn.cursor()

    print("=" * 45)
    print("       SIEM DAILY THREAT INTEL REPORT        ")
    print("=" * 45)

    # 2. Query 1: Calculate Total Failed Attacks
    cursor.execute("SELECT COUNT(*) FROM auth_events WHERE event_type = 'failed'")
    total_failures = cursor.fetchone()[0]
    print(f"[*] Total Malicious Login Failures: {total_failures}")
    print("-" * 45)

    # 3. Query 2: Aggregate Top 5 Targeted Usernames
    # Using a triple-quoted multi-line string preserves spaces naturally
    top_targets_query = """
        SELECT user_id, COUNT(*) as total 
        FROM auth_events 
        WHERE event_type = 'failed'
        GROUP BY user_id 
        ORDER BY total DESC 
        LIMIT 5
    """
    cursor.execute(top_targets_query)
    top_accounts = cursor.fetchall()

    print("[*] Top 5 Most Target Account Usernames:")
    if not top_accounts:
        print("    No brute force logs recorded yet.")
    else:
        for index, row in enumerate(top_accounts, start=1):
            username = row[0]
            attack_count = row[1]
            print(f"    {index}. Account: '{username}' -> Attacked {attack_count} times")

    print("=" * 45)

    # 4. Clean up handle
    conn.close()


if __name__ == "__main__":
    run_analytics_report()

