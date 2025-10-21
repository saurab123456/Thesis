import json

DEDUP_FILE = "./alerts_data/deduplicated_alerts.json"

def inspect_alerts(file_path, limit=10):
    with open(file_path, "r") as f:
        count = 0
        for line in f:
            if count >= limit:
                break
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            print(f"\nAlert #{count+1}:")
            # Print top-level keys
            print("Top-level keys:", list(alert.keys()))

            # Print 'data' keys and values if present
            data = alert.get("data", {})
            print("'data' keys and values:")
            for key in ["srcip", "dstip", "srcport", "dstport", "proto"]:
                print(f"  {key}: {data.get(key, '(missing)')}")

            # Also print a snippet of 'full_log' for context
            full_log = alert.get("full_log", "")
            print("full_log snippet:", full_log[:100] + "..." if full_log else "(missing)")

            count += 1

if __name__ == "__main__":
    inspect_alerts(DEDUP_FILE)
