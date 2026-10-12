import json
import os

DB_FILE = "threat_repo.json"

def load_repo():
    """Loads the known attacks database."""
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {} # Return empty dict if no database exists yet

def save_repo(db_data):
    """Saves the updated attacks back to the database."""
    with open(DB_FILE, "w") as f:
        json.dump(db_data, f, indent=4)

def process_alert(alert_data, attack_signature):
    # Step 1: Load the current database
    repo = load_repo()
    
    # Step 2: Check if this attack is already known
    if attack_signature in repo:
        repo[attack_signature]["frequency"] += 1
        save_repo(repo)
        
        return {
            "status": "Known Threat Signature – Pulled from Repository",
            "summary": repo[attack_signature]["summary"],
            "frequency": repo[attack_signature]["frequency"]
        }
    
    # Step 3: If novel, call Gemini (Simulated here)
    # response = call_gemini_api(alert_data)
    gemini_summary = "An attacker scanned the network and uploaded a webshell." # Placeholder
    
    # Step 4: Save the novel attack to the persistent database
    repo[attack_signature] = {
        "summary": gemini_summary,
        "frequency": 1
    }
    save_repo(repo)
    
    return {
        "status": "Novel Threat Detected – Deep Analysis Required",
        "summary": gemini_summary,
        "frequency": 1
    }