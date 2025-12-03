<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>

<h1 align="center">Ala Dabat</h1>
<h3 align="center">Senior SOC / Incident Response / Threat Intelligence Analyst</h3>

<p align="center">
  <strong>Detection Engineering • Threat Intelligence • Adversary Behaviour • KQL • MDE • Sentinel • Falcon LQL (later project due to testing evnvironment or lackthereof) </strong>
</p>

> [!NOTE]  
> This portfolio is actively evolving. Many hunts are complete and production-ready; others are being tuned, validated and expanded with scoring models, baselines, and full kill-chain mapping.  
> The repository reflects a live engineering process, where new rules, matrices and SOPs are continuously refined against modern attack patterns. Basic hunt pack will eventually be included all in due course.

---

# About This Portfolio

This repository documents my work as a detection engineer and threat hunter.  
My focus is on **intelligence-driven detection logic** that reflects how real attackers operate, not just IOC matching.  

The work here represents:
- Behaviour-first detection engineering in KQL  
- High-fidelity hunts with scoring, rarity analysis and baseline controls  
- Supply-chain, identity and post-exploitation modelling  
- LOLBins, persistence, lateral movement and C2 behaviour analysis  
- Structured triage guidance tailored for SOC analysts  
- End-to-end attack chain reconstruction using MITRE and custom kill-chain markers  

The goal is simple: produce **operationally useful** detection content that SOC and IR teams can run immediately.

---

# My Detection Engineering Methodology

## 1. Behaviour-Driven Analytics
Rules begin by defining attacker **actions**, not strings or single events:
- What would a real operator do at this stage?
- What assets, privileges or telemetry footprint must they touch?
- How do I capture the *behaviour* instead of the tool?

This ensures durability against tool changes, polymorphism, and evasion.

---

## 2. Adversary Mapping & Threat Modelling

Every hunt maps to:
- **MITRE Tactics → Techniques → Sub-techniques**  
- **Attack chains**: Recon → Initial Foothold → PrivEsc → Credential Access → Lateral Movement → Collection → Exfiltration
- **Threat categories**: supply-chain, credential theft, identity abuse, RCE chains, stealth C2, persistence

Threat modelling is done using:
- Known campaign behaviour (SolarWinds, 3CX, NotPetya, APT41, APT29, 3CX, F5, Kaseya-style supply chain)
- TTP generalisation (DLL sideloading lifecycle, driver abuse, registry implants, ROPC abuse, OAuth consent abuse)
- Infrastructure behaviour (jittered beacons, domain fronting, TOR relays, redirectors)
- Tradecraft patterns: “How would I do this if I were the adversary and wanted to avoid telemetry?”

---

## 3. Scoring Models & Confidence Weighting

All core hunts in this repo use a scoring approach that considers:
- Rarity  
- Parent/child lineage  
- Path legitimacy  
- Signing trust  
- Registry vs file vs network correlation  
- Kill-chain alignment  
- Host criticality (DC, server, exposed system)  

This provides a practical **signal-to-noise ratio** and lets analysts prioritise rapidly.

---

## 4. Hunter Directives Framework

Every rule includes short operational guidance:
- What to check next  
- How to pivot across telemetry  
- What normally causes this benignly  
- Indicators of escalation  
- Recommendations if malicious  

This is written for real SOC analysts—concise and actionable.

---

# MITRE Threat Landscape & LOLBins SOP Framework (Included Across Rulepacks)

I maintain SOPs for all major LOLBins used in:
- Execution  
- Defense evasion  
- Fileless activity  
- Credential access  
- Lateral movement  
- Persistence injection  

Each LOLBin entry includes:
- Normal usage profile  
- Abuse scenarios  
- Related MITRE techniques  
- Command-line artefacts  
- Detection artefacts  
- Recommended KQL pivots  
- Response steps  

This forms a **living library** of adversary behaviour and defensive mappings.

---

# MITRE ATT&CK Mapping

All rules follow a uniform standard:
- Tactics listed explicitly  
- Techniques derived from behaviour, not guesswork  
- Sub-techniques included when they map clearly  
- Technique selection aligned with real tradecraft (e.g. NTDS = T1003.003 + T1552 + T1110 pivot cases)

MITRE mapping is not cosmetic—it guides:
- Kill-chain placement  
- Scoring weighting  
- Pivot logic  
- Hunter directives  

---

# Attack Chain Modelling

Many hunts explicitly identify the attack phase:
- Initial Execution  
- Privilege Escalation  
- Credential Access  
- Persistence  
- Collection  
- Exfiltration  

Kill-chain detection improves:
- Scoring
- Triage priority
- Correlation across tables
- Timing windows for multi-step attacks  

---

# Repository Structure

## 1. **Threat-Hunting-Rules**
High-fidelity KQL hunts with:
- Scoring & confidence models  
- Kill-chain mapping  
- Rarity and baseline logic  
- Hunter directives  
- Comprehensive MITRE mappings  
- Native-only variants (no TI dependency)  
- Supply-chain detection rules (DLL/driver/sideloading lifecycle)  
- Identity-based rules (ROPC, OAuth consent, MFA bypass patterns)  
- Jittered HTTPS beaconing / C2 timing analytics  
- NTDS.dit and DCSync chain detection  
- WSL PrivEsc & persistence hunts  
- Registry persistence scoring engine  
- LOLBins-based privilege escalation & access rules
- 0Auth Abuse & Detection Engineering
- Rogue Device and Device Anomaly Unified rule
- Polymorphic Malware Coore Hunts, L3 Engineering Rule
  etc...

Each rule is engineered to meet:
- Low noise  
- High fidelity  
- Operational value in a SOC  

---

# 2. **Threat Modelling & Research**
- Campaign mapping (APT29, APT41, 3CX, F5, SolarWinds examples)  
- Code execution chains (DLL, driver, COM hijack, IFEO)  
- C2 infrastructure (jitter analysis, beacon timing, redirectors)  
- BYOVD and kernel exploit patterns  
- Identity-led intrusions
- Threat Lanscape 2023--> 2024 --> 2025

---

# 3. **Incident Response Playbooks**
In progress:
- NTDS exfil playbook  
- Account compromise and token theft response  
- DLL sideloading triage  
- Driver abuse / BYOVD response  

---

# Roadmap & Ongoing Work

The next phase includes:
- Enterprise baseline tuning  
- Noise-vs-signal matrices per rule  
- Test datasets and demo outputs  
- MITRE coverage scoring and mapping heatmaps  
- Automated packaging of rulepacks  
- Red-team/Blue-team joint modelling guides  

This repository is intentionally iterative. Each week I refine:
- Field correctness  
- Scoring weights  
- Kill-chain logic  
- Hunter directive clarity  
- Noise reduction  

This mirrors real-world detection engineering workflows.

## Threat Hunting Rule Philosophy

This repository contains **behaviour-driven Threat Hunting rules** designed for use by L2/L3 analysts, Incident Responders, and Threat Hunters.

These are **not signature-based detections** or SOC alert rules.  
Instead, each analytic is built to:

- Identify *patterns* rather than single IOC events  
- Map directly to **MITRE ATT&CK tactics and techniques**  
- Support **hypothesis-driven hunting**, not passive alerting  
- Highlight anomalies in **execution flow, persistence, lateral movement, and C2**  
- Provide **Hunting Directives**: recommended analyst pivots and triage steps  
- Introduce **weighted scoring** and *signal accumulation*, rather than Boolean matching  
- Reconstruct portions of the **attack chain** from endpoint + cloud telemetry  
- Surface *weak signals* that attackers rely on during stealthy operations  
- Reduce uncertainty by correlating across multiple data sources (Process, File, Registry, Network)

These rules intentionally prioritise **recall and behavioural depth** over precision, making them ideal for:

- Weekly hunting cycles  
- Monthly environment baselining  
- Compromise assessments  
- Incident response investigations  
- Purple team exercises  
- Detection gap analysis
## LOLBin SOP Framework

Many hunts in this repository incorporate a structured **LOLBIN (Living-Off-The-Land Binary) SOP**, which includes:

- Known legitimate usage patterns  
- Abnormal command-lines  
- Expected parent-child relationships  
- Registry and file system indicators  
- Execution contexts that raise suspicion (SYSTEM, user-writable paths, unsigned binaries)  
- Pivot guidance for each technique  
- MITRE mappings for each LOLBin family  
- Recommended response actions
  There will also be a project covering most attack vectors using the same SOP methadology. 

---

# Contact
**GitHub:** https://github.com/azdabat  
**Email:** azdabat193@gmail.com  
**Location:** United Kingdom  

<p align="center"><i>“Intelligence-driven detection engineering — translating adversary behaviour into measurable defensive depth.”</i></p>
