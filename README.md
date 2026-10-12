🛡️ FalconBrief: Autonomous Alert Triage & Adaptive Caching Engine
Track: Track 1 (Plain-English Alert Translator) & The Ciocca Venture Award

The Problem
Security Operations Centers (SOCs) face two massive bottlenecks today:

Alert Fatigue: Tier-1 junior analysts spend 15–20 minutes deciphering cryptic, raw IDS and endpoint telemetry (Wazuh, Suricata, AMiner) before they can take action.

LLM Latency & Compute Costs: While generative AI can translate these alerts, querying an LLM for every single alert in a network of 10,000 endpoints is too slow and too expensive. (During this very hackathon, API congestion caused severe LLM latency—proving that relying solely on live AI generation during an active cyberattack is not a viable enterprise strategy).

 The Solution
FalconBrief is an autonomous alert triage tool that ingests raw telemetry clusters, identifies key attack signatures, and produces instant, three-part plain-English briefings. It solves the LLM latency bottleneck via an Adaptive Threat Repository that fingerprints attack behaviors.

Instead of generating a new AI response for every alert, FalconBrief only uses the LLM for novel threats. It caches the intelligence locally, dropping response times from several seconds to under 0.05 seconds for repeat campaigns.

Key Capabilities
Instant Incident Briefings: Translates complex JSON logs into a one-sentence Executive Summary, maps the attack to MITRE ATT&CK tactics, and provides a prioritized 3-step remediation checklist.

Smart Threat Fingerprinting: Dynamically extracts the core Attack Type and Attacker IP from raw logs to build a behavioral signature, ensuring attackers cannot bypass the cache by simply mutating timestamps or ports.

Mutated Campaign Detection: If an attacker changes their IP address but utilizes a known attack methodology, FalconBrief detects the pattern, pulls historical threat intel from the local database, and injects it into the LLM context to accelerate analysis.

Exact Duplicate Prevention: Hashes incoming telemetry to prevent analysts from burning API compute on data that has already been triaged.

Cost Reduction: Cuts LLM API operating expenses by nearly 100% on active, repeated attack campaigns via local signature caching.

Efficiency: Reduces MTTR (Mean Time to Respond) by delivering localized threat intelligence instantly, bypassing cloud LLM latency entirely.

🛠️ Architecture & Tech Stack
Frontend: Streamlit

AI Engine: Google Gemini 3.8 Flash

Dataset: AIT Alert Data Set (Zenodo 8263181) — Real-world Wazuh & AMiner multi-stage attack scenarios.
