#!/usr/bin/env python3
"""
visualize_alerts.py
Generate visualizations from wazuh.db:
1. Pie chart: TP vs FP ratio
2. Bar chart: Top 10 external attacker IPs (true positives)
3. Bar chart: Top 10 noisy alert rules (false positives)
"""

import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DB_PATH = "/home/ubuntu/wazuh-logs/wazuh.db"

def fetch_df(query):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# 1) TP vs FP ratio
q_labels = """
SELECT is_important, COUNT(*) as cnt
FROM ml_labels
GROUP BY is_important;
"""
df_labels = fetch_df(q_labels)

plt.figure(figsize=(6,6))
labels_map = {0: "False Positives (Noise)", 1: "True Positives (Attacks)"}
plt.pie(df_labels["cnt"], labels=[labels_map[i] for i in df_labels["is_important"]],
        autopct='%1.1f%%', startangle=140)
plt.title("TP vs FP Ratio in Alerts")
plt.savefig("tp_fp_ratio.png")
plt.close()

# 2) Top 10 external attackers
q_attackers = """
SELECT srcip, COUNT(*) as cnt
FROM wazuh_events
WHERE _id IN (SELECT id FROM ml_labels WHERE is_important = 1)
  AND srcip NOT LIKE '10.%'
GROUP BY srcip
ORDER BY cnt DESC
LIMIT 10;
"""
df_attackers = fetch_df(q_attackers)

plt.figure(figsize=(10,6))
plt.bar(df_attackers["srcip"], df_attackers["cnt"])
plt.xticks(rotation=45, ha="right")
plt.title("Top 10 External Attackers (True Positives)")
plt.xlabel("Source IP")
plt.ylabel("Count")
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.close()

# 3) Top 10 noisy rules
q_noise = """
SELECT rule_description, COUNT(*) as cnt
FROM wazuh_events
WHERE _id IN (SELECT id FROM ml_labels WHERE is_important = 0)
GROUP BY rule_description
ORDER BY cnt DESC
LIMIT 10;
"""
df_noise = fetch_df(q_noise)

plt.figure(figsize=(10,6))
plt.barh(df_noise["rule_description"], df_noise["cnt"])
plt.gca().invert_yaxis()  # most frequent on top
plt.title("Top 10 Noisy Rules (False Positives)")
plt.xlabel("Count")
plt.ylabel("Rule Description")
plt.tight_layout()
plt.savefig("top_noisy_rules.png")
plt.close()

print("✅ Charts saved: tp_fp_ratio.png, top_attackers.png, top_noisy_rules.png")
