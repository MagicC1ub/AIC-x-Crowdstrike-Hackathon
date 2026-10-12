import streamlit as st
import json
import os
import time
import google.generativeai as genai
import re
import hashlib
from dotenv import load_dotenv

# --- 1. Securely Load the API Key ---
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")
if not api_key:
    st.error("Missing GEMINI_API_KEY. Please check your .env file.")
    st.stop()

genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-3.8-flash')

DB_FILE = "threat_repo.json"

# --- 2. Database Caching Functions ---
def load_repo():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {}

def save_repo(db_data):
    with open(DB_FILE, "w") as f:
        json.dump(db_data, f, indent=4)

# --- 3. Gemini Prompt Engineering ---
def analyze_with_gemini(alerts_data, attack_type, historical_context=None):
    raw_telemetry = json.dumps(alerts_data)[:8000] 
    
    prompt = f"You are a senior SOC analyst triaging a suspected {attack_type} attack.\n"
    
    if historical_context:
        prompt += f"""
        CRITICAL THREAT INTEL: We have seen this exact attack type before from a different source. 
        Previous Analysis: {historical_context}
        
        INSTRUCTIONS: Review the new telemetry. Because this matches a known attack pattern, ACCELERATE your analysis. Reuse the previous MITRE mapping and Remediation steps if they still apply. Focus strictly on updating the Executive Summary to reflect the new attacker IP and identifiers.
        """
        
    prompt += f"""
    Provide a briefing formatted exactly with these three Markdown headers:
    ### 1. Executive Summary
    ### 2. MITRE ATT&CK Mapping
    ### 3. Immediate Remediation
    
    Raw Telemetry:
    {raw_telemetry}
    """
    
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error connecting to Gemini API: {e}"

# --- 4. Streamlit User Interface ---
st.set_page_config(page_title="FalconBrief Triage", layout="wide", page_icon="🛡️")
st.title("🛡️ FalconBrief: Autonomous Alert Triage")
st.markdown("Upload flagged telemetry clusters from your IDS/SIEM to generate instant incident briefings.")
st.markdown("---")

uploaded_file = st.file_uploader("Upload Raw Telemetry (JSON)", type=["json"])

if uploaded_file is not None:
    if st.button("Analyze Threat Telemetry", key="main_analyze_btn"):
        
        # Read and hash the file to check for exact duplicates
        file_bytes = uploaded_file.read()
        file_hash = hashlib.md5(file_bytes).hexdigest()
        data = json.loads(file_bytes.decode('utf-8'))
        
        repo = load_repo()
        
        # --- FEATURE 1: Check for Exact Duplicate File Uploads ---
        if "SEEN_FILES" not in repo:
            repo["SEEN_FILES"] = []
            
        if file_hash in repo["SEEN_FILES"]:
            st.warning("⚠️ **Duplicate Upload Detected:** You have already analyzed this exact telemetry payload. The results below are pulled from the cache.")
        else:
            repo["SEEN_FILES"].append(file_hash)
            save_repo(repo)

        # Extract IP and Attack Type
        raw_logs_str = json.dumps(data.get('wazuh_logs', []) + data.get('aminer_logs', []))
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_logs_str)
        attacker_ip = max(set(ips), key=ips.count) if ips else "Unknown_IP"
        
        attack_type = data.get('attack_type', 'UNKNOWN').upper()
        attack_signature = f"{attack_type}_SOURCE_{attacker_ip}"
        
        # --- 1. Exact Cache Hit Branch (Same Attack, Same IP) ---
        if attack_signature in repo:
            start_time = time.time()
            # Only increment frequency if it's a genuinely NEW file matching the signature, not the exact same file re-uploaded
            if file_hash not in repo.get("SEEN_FILES", [])[:-1]: 
                repo[attack_signature]["frequency"] += 1
                save_repo(repo)
                
            retrieval_time = time.time() - start_time
            
            st.success(f"🟢 Known Threat Signature ({attack_signature}) – Pulled from Local Cache")
            
            # --- FEATURE 2: Persistent Threat Warning ---
            if repo[attack_signature]["frequency"] > 1:
                st.error(f"🚨 **CRITICAL - PERSISTENT THREAT:** The exact same {attack_type} attack has now occurred **{repo[attack_signature]['frequency']} times** from the exact same IP address ({attacker_ip}). Your previous remediation efforts have failed or the endpoint is completely compromised.")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Response Time", f"{retrieval_time:.4f}s", "-99.8% vs LLM")
            col2.metric("Compute Cost", "$0.000", "-100% API Savings")
            col3.metric("Occurrences Logged", f"{repo[attack_signature]['frequency']}x")
            
            st.markdown("---")
            st.markdown(repo[attack_signature]["summary"])
            
        else:
            start_time = time.time()
            
            # --- 2. Search for Historical Context (Same Attack, New IP) ---
            historical_intel = None
            for key, intel in repo.items():
                if key != "SEEN_FILES" and attack_type in key:
                    historical_intel = intel["summary"]
                    break
            
            if historical_intel:
                st.warning(f"🟡 Mutated Campaign Detected ({attack_signature}) – Cross-Referencing Threat Repo")
            else:
                st.error(f"🔴 Novel Threat Detected ({attack_signature}) – Deep Telemetry Analysis Required")
            
            # --- 3. Execute LLM with or without Context ---
            with st.spinner("Analyzing telemetry with Gemini 3.8 Flash..."):
                gemini_summary = analyze_with_gemini(data, attack_type, historical_intel)
                analysis_time = time.time() - start_time
                
                repo[attack_signature] = {
                    "summary": gemini_summary,
                    "frequency": 1
                }
                save_repo(repo)
                
            col1, col2, col3 = st.columns(3)
            col1.metric("LLM Analysis Time", f"{analysis_time:.2f}s")
            col2.metric("API Compute", "Gemini 3.8 Flash")
            col3.metric("Status", "Cached to Repository")
            
            st.markdown("---")
            st.markdown(gemini_summary)