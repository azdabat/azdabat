<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>

<h1 align="center">Ala Dabat</h1>
<h3 align="center">Senior SOC / Incident Response / Threat Intelligence Analyst</h3>

<p align="center">
  <strong>Detection Engineering • Threat Intelligence • Adversary Behaviour • KQL • MDE • Sentinel • Falcon LQL</strong>
</p>

> **Note**  
> This portfolio is active and evolving. Core logic is complete and functional, with further tuning, new hunts, and additional coverage being added incrementally. Many rules have already been redesigned for low-noise, high-signal production alignment.

---

# About Me

I specialise in **intelligence-led detection engineering**, advanced **threat hunting**, and **adversary behaviour analysis** across enterprise cloud and endpoint environments. My work focuses on taking real-world intrusion tradecraft and converting it into **structured, repeatable, high-fidelity detections**.

Areas I actively work on include:

- Behaviour-driven KQL / LQL rule design  
- MITRE ATT&CK mapping and kill-chain modelling  
- Identity-based attack detection (OAuth abuse, legacy protocol misuse, token theft)  
- Supply-chain attack modelling (SolarWinds, 3CX, F5, NotPetya)  
- DLL/driver sideloading, BYOVD, and component hijacking  
- C2 beaconing detection via timing, jitter, process lineage, and rare-path signals  
- Threat Intelligence ingestion (MISP/OpenCTI) and enrichment design  
- Incident response reconstruction and adversary pivot analysis  

This repository is structured to provide **operationally useful detection artefacts**: rulepacks, scoring frameworks, MITRE mappings, pivot guides, and hunter-friendly triage notes.

---

# Core Focus Areas

- Endpoint + Cloud detection engineering (MDE / Sentinel)  
- Adversary tradecraft modelling  
- Threat Intelligence workflows (MISP, OpenCTI, STIX/TAXII)  
- High-confidence, low-noise hunts covering persistence, identity, C2, and lateral movement  
- Incident response and attack-path reconstruction  
- Red-team TTP replication to validate defensive coverage  

---

# Portfolio Overview

## Threat Intelligence
- Campaign and infrastructure mapping  
- IOC/indicator processing pipelines  
- Correlation and confidence scoring logic  
- MITRE ATT&CK coverage heatmaps  

## Threat Hunting & Incident Response
- Endpoint/cloud telemetry correlation  
- Credential theft analysis (LSASS, DPAPI, NTDS)  
- Lateral movement, SMB/WinRM/AD abuse  
- Kill-chain reconstruction and reporting  

## Research & Adversary Simulation
- Supply-chain intrusion modelling  
- DLL/driver sideloading and BYOVD behaviour analysis  
- C2 timing, jitter, and protocol studies  
- Polymorphic malware behaviour profiling  

---

# Repository Structure

This portfolio is divided into several practical components used by SOC, IR, and TI teams:

## 1. Detection Engineering (Primary Work)
High-fidelity KQL rules aligned to MITRE with:
- Confidence scoring  
- Signal weighting  
- Kill-chain classification  
- Hunter directives  
- Native-only and hybrid TI/CTI variants  

Rules are structured for **real-world analyst use**, not academic demonstrations.

Repository: **Threat-Hunting-Rules**  
https://github.com/azdabat/Threat-Hunting-Rules

---

# Roadmap (In Progress)

The following areas are actively expanding as part of the November–January development cycle:

- Final tuning of supply-chain / sideloading / driver rules  
- Completion of OAuth / identity abuse detection pack  
- NTDS / DCSync native correlation pack  
- Jitter-based C2 detection improvements  
- Baseline models for known-good processes and publishers  
- Integrated “quick-start” hunt guide and MITRE coverage matrix  

Each module is being iterated and hardened based on production environments and current 2024–2025 intrusion trends.

---

# Contact

**GitHub:** https://github.com/azdabat  
**Email:** azdabat193@gmail.com  
**Location:** United Kingdom  

<p align="center"><i>“Intelligence-driven detection engineering — translating adversary behaviour into measurable defensive depth.”</i></p>
