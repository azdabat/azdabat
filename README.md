<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>

<h1 align="center">Ala Dabat</h1>
<h3 align="center">Senior Threat Hunter • Detection Engineer • Advanced MDR / Purple Team</h3>

<p align="center">
  <strong>
    Behavioural Detection Engineering • Adversary Tradecraft • Kill-Chain Correlation • KQL • Microsoft Defender for Endpoint • Microsoft Sentinel • CrowdStrike (LQL)
  </strong>
</p>

> **Status:** Actively evolving detection engineering portfolio  
> This repository reflects a live engineering process. Core hunts are production-ready; advanced hunts are continuously refined, pressure-tested, and validated in lab environments (ADX + Elastic + Atomic Red Team).

---

## About This Repository

This GitHub documents my work as a **detection engineer and threat hunter**, focused on **behaviour-led, adversary-informed detection** rather than static IOC or signature matching.

The emphasis throughout this repository is on:

- How real attackers operate in enterprise environments  
- How detections fail in production  
- How to design analytics that survive evasion, tooling changes, and noise  
- How SOC analysts actually investigate incidents under pressure  

This is **engineering work**, not academic theory.

# Threat Modelling SOP: Behavioral & Patch-Resistant TTPs

##  Engineering Philosophy
This repository houses L3 "Hardened" detection logic designed for **Patch-Resistant Threats**—native Windows components (WMI, Registry, LOLBins) that adversaries abuse but cannot be blocked.

###  The "Atomic Cluster" Methodology
I do not write 1:1 detections for individual tools (e.g., *Mimikatz* vs. *ProcDump*). This leads to alert fatigue. Instead, I group Atomic Red Team tests into **Behavioral Clusters**:

1.  **Cluster:** Identify the shared underlying behavior across multiple Atomics (e.g., *T1003 - LSASS Handle Access*).
2.  **Abstract:** Write a single **Composite Rule** (Sigma/KQL) that detects the behavior, not the tool hash.
3.  **Validate:** Logic is tested against the full Atomic suite in Azure Data Explorer (ADX) to ensure <5% False Positive rates.

### ADX Roadmap (Q1 2026)
* **Current Status:** Endpoint Telemetry (Process/Registry/WMI etc..) is **L2.5/L3 Hardened**.
* **Next Sprint:** Expanding coverage to **Network Correlation** (Zeek/Corelight) to detect C2 channels (e.g., Blockchain RPC beaconing) for compromised hosts.
---

## Core Principles

### 1. Behaviour Before Tools
Detections are built around **attacker behaviour**, not binaries, hashes, or vendor-specific indicators.

Questions that drive every rule:
- What *must* the adversary do at this stage?
- What telemetry surfaces cannot be avoided?
- How would this be executed quietly in a real environment?

This makes detections durable against:
- Polymorphism  
- Living-off-the-land abuse  
- Signed binary misuse  
- Fileless and in-memory tradecraft  

---

### 2. Attack-Chain First Design
All hunts model **attack progression**, not isolated events.

Typical chains covered:
Recon → Initial Access → Execution → Persistence → Privilege Escalation → Credential Access → Lateral Movement → Command & Control → Exfiltration

Rules are intentionally split when:
- Execution models differ (process-based vs process-less)
- Telemetry cost differs (light vs heavy)
- Tuning domains differ (workstations vs servers vs IT automation)

This avoids fragile “god rules” and reduces SOC noise.

---

### 3. Adversary-Informed Threat Modelling
Threat modelling is based on **real campaigns and generalized tradecraft**, not vendor blogs.

Includes:
- Supply-chain attacks (SolarWinds, 3CX, Kaseya-style)  
- Identity abuse (OAuth consent, token misuse, ROPC)  
- LOLBin lifecycles (rundll32, mshta, wmic, wsl, certutil, etc.)  
- Persistence mechanisms (WMI, registry implants, services, drivers)  
- Infrastructure patterns (low-prevalence C2, redirectors, jittered beacons)  

The question is always:
> *“How would I do this if I wanted to avoid detection?”*

---

### 4. Scoring & Signal Accumulation
Detections use **weighted scoring**, not boolean logic.

Signals commonly include:
- Rarity / prevalence  
- Parent-child lineage trust  
- Path legitimacy  
- Signing and publisher context  
- Multi-surface correlation (process + file + registry + network)  
- Kill-chain alignment  
- Host criticality (DCs, servers, exposed systems)

This allows analysts to prioritise **risk**, not alerts.

---

### 5. Analyst-First Output (Hunter Directives)
Every hunt includes **concise operational guidance**, not walls of text.

Each rule answers:
- Why this fired  
- What to pivot on next  
- Common benign causes  
- Escalation indicators  
- Recommended response actions  

Written for **real SOC analysts**, not slide decks.

---

## Validation & Pressure Testing

Advanced hunts are validated using:
- **Atomic Red Team** (controlled tradecraft execution)
- **ADX Docker** (KQL correlation and scoring validation)
- **Elastic** (timeline reconstruction and raw telemetry review)

Validation focuses on:
- Telemetry existence (before tuning logic)
- True-positive fidelity
- Noise behaviour under baseline conditions
- Known blind spots (explicitly documented)

This repository favours **honesty over false completeness**.

---

## Detection Framework Overview

Threat Modelling
→ ATT&CK mapping, adversary behaviour, execution models

Telemetry Mapping
→ Process, File, Registry, Network, Identity, WMI, Drivers

Behavioural Signal Extraction
→ Rare flows, lineage breaks, substrate requirements

Scoring & Confidence
→ Rarity, trust, context, kill-chain alignment

Correlation
→ Multi-table joins, time-window linkage, enrichment

Analyst Output
→ Human-readable triage guidance and pivots

Pressure Testing
→ Noise simulation, Atomic validation, refinement


---

## Telemetry Surfaces Used

| Behaviour Surface | Primary Telemetry |
|------------------|------------------|
| Process Execution | DeviceProcessEvents |
| File Activity | DeviceFileEvents |
| Registry Activity | DeviceRegistryEvents |
| Network Behaviour | DeviceNetworkEvents |
| Identity & Logons | SigninLogs, DeviceLogonEvents |
| Driver / Kernel | DeviceEvents (DriverLoad) |
| WMI / Persistence | Sysmon + WMI Activity |

---

## Repository Structure

| Path | Purpose |
|-----|--------|
| `/core-hunts/` | Low-noise behavioural hunts for routine SOC operations |
| `/engineering/` | Advanced detection engineering & correlation rules |
| `/matrices/` | MITRE mappings, coverage tables, cheat sheets |
| `/docs/` | Methodology, IR workflows, SOPs |
| `/samples/` | Test data and demonstration outputs |

---

## Intended Use

These hunts are designed for:
- L2/L3 SOC analysts  
- Threat hunters  
- Detection engineers  
- MDR / IR teams  
- Purple team exercises  
- Detection gap analysis  

They prioritise **behavioural depth and recall** over alerting precision.

---

## Philosophy

1. Behaviour before signatures  
2. Correlation before alerts  
3. Context over noise  
4. Transparency about blind spots  
5. Engineering depth with hunter agility  

This repository reflects how **modern detection engineering is actually done** in production environments.

---

## Contact

**GitHub:** https://github.com/azdabat  
**Email:** azdabat193@gmail.com  
**Location:** United Kingdom  

<p align="center"><i>
“Intelligence-led detection engineering — translating adversary behaviour into measurable defensive depth.”
</i></p>
