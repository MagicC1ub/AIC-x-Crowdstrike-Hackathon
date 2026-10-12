# FalconBrief: Autonomous Alert Triage & Adaptive Caching Engine

> Built for the **AIC x CrowdStrike Hackathon** (Track 1: Plain-English Alert Translator & The Ciocca Venture Award).

## Executive Problem
Security Operations Centers (SOCs) face severe alert fatigue. Tier-1 junior analysts spend an average of 15–20 minutes deciphering cryptic, raw IDS and endpoint telemetry (Wazuh, Suricata, AMiner). Escalating routine alerts overwhelms senior staff and inflates Mean Time to Respond (MTTR).

## The Solution
**FalconBrief** ingests raw security telemetry clusters, identifies key attack signatures, and produces instant, three-part plain-English briefings:
1. **Executive Summary** (One-sentence non-technical summary)
2. **MITRE ATT&CK Mapping** (Exact tactics & techniques)
3. **Immediate Remediation** (Prioritized action checklist)

### The Ciocca Venture: Dynamic IoC Caching
Enterprise LLM deployments face high latency and token costs. FalconBrief solves this via an **Adaptive Threat Repository**:
* **Novel Attacks:** Processed through Gemini 3.8 to generate structured threat intelligence (~3s latency).
* **Known Attacks:** Fingerprinted and retrieved instantly from the local threat cache (<0.01s latency, zero token cost).
* **Threat Frequency Tracking:** Informs the analyst if an incident is an isolated anomaly or an active, repeated campaign.

---

## Architecture & Tech Stack
* **Frontend:** Streamlit
* **AI Engine:** Google Gemini 3.8
* **Dataset:** AIT Alert Data Set (Zenodo 8263181) — Real-world Wazuh & AMiner multi-stage attack scenarios.
* **Storage:** Persistent JSON Threat Cache

---

## Quickstart

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd AIC-x-Crowdstrike