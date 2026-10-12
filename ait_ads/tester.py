import pandas as pd
import json
import os
from datetime import datetime

labels_df = pd.read_csv("labels.csv")

DEMO_CASES = [
    {"scenario": "fox", "attack": "webshell"},
    {"scenario": "wardbeck", "attack": "privilege_escalation"}
]

master_test_document = {}
BUFFER_SECONDS = 60 

def filter_logs(filepath, start_time, end_time):
    filtered_alerts = []
    if not os.path.exists(filepath):
        return filtered_alerts
        
    adjusted_start = start_time - BUFFER_SECONDS
    adjusted_end = end_time + BUFFER_SECONDS
        
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue 
                
            try:
                log = json.loads(line)
                
                raw_time = None
                if log.get("timestamp"):
                    raw_time = log.get("timestamp")
                elif log.get("@timestamp"):
                    raw_time = log.get("@timestamp")
                elif log.get("LogData") and log["LogData"].get("Timestamps"):
                    raw_time = log["LogData"]["Timestamps"][0]
                    
                if not raw_time:
                    continue
                
                if isinstance(raw_time, str):
                    try:
                        clean_time = raw_time.replace("Z", "+00:00")
                        dt_obj = datetime.fromisoformat(clean_time)
                        log_time = dt_obj.timestamp()
                    except ValueError:
                        continue 
                else:
                    log_time = float(raw_time) 
                
                if adjusted_start <= log_time <= adjusted_end:
                    filtered_alerts.append(log)
                    
            except Exception:
                pass
                
    return filtered_alerts

for index, row in labels_df.iterrows():
    scenario = row['scenario']
    attack = row['attack']
    start = float(row['start'])
    end = float(row['end'])
    
    wazuh_file = f"{scenario}_wazuh.json"
    aminer_file = f"{scenario}_aminer.json"
    
    wazuh_alerts = filter_logs(wazuh_file, start, end)
    aminer_alerts = filter_logs(aminer_file, start, end)
    
    attack_key = f"{scenario}_{attack}"
    
    combined_alerts = {
        "scenario": scenario,
        "attack_type": attack,
        "wazuh_logs": wazuh_alerts,
        "aminer_logs": aminer_alerts
    }
    
    master_test_document[attack_key] = combined_alerts
    
    for demo in DEMO_CASES:
        if scenario == demo["scenario"] and attack == demo["attack"]:
            demo_filename = f"demo_{attack_key}.json"
            with open(demo_filename, 'w') as demo_file:
                json.dump(combined_alerts, demo_file, indent=4)
            print(f"Exported demo file: {demo_filename} with {len(wazuh_alerts) + len(aminer_alerts)} total alerts.")

with open("master_test_cases.json", 'w') as master_file:
    json.dump(master_test_document, master_file)
print("Exported master_test_cases.json")