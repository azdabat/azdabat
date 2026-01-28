<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>


<h1 align="center">Ala Dabat</h1>
<h3 align="center">Senior Threat Hunter • Detection Engineer • Advanced MDR / Purple Team</h3>

<p align="center">
  <strong>
    Behavioural Detection Engineering • Adversary Tradecraft • Kill-Chain Correlation • KQL  
    Microsoft Defender XDR • Microsoft Sentinel • CrowdStrike Falcon (LQL)
  </strong>
</p>

> **Portfolio Status**  
> This repository documents an active, production-oriented detection engineering framework.  
> Composite hunts are logically production-safe; final noise calibration is performed per-tenant once live telemetry and admin workflows are available.

---

## Executive Summary

This GitHub documents my work as a **detection engineer and threat hunter** focused on **behaviour-first, adversary-informed analytics**.

I design detections that:
- survive tooling changes
- remain effective after patching
- tolerate enterprise noise
- support analysts under real operational pressure

This is **engineering work**, not IOC curation or academic modelling.

---

## Core Detection Philosophy

### The Composite Detection Framework

All detections follow a consistent structure:

**Minimum Truth → Reinforcement → Scoring → Analyst Action**

- **Minimum Truth**  
  The non-negotiable event that *must* occur for an attack to exist  
  (e.g. LSASS memory access, OAuth consent grant, WMI consumer execution)

- **Reinforcement**  
  Context added only when baseline behaviour overlaps with legitimate operations  
  (e.g. network activity, lineage breaks, writable paths)

- **Scoring & Confidence**  
  Signals accumulate to express *risk*, not binary alerts

- **Hunter Directives**  
  Clear next steps for L1–L3 analysts: pivots, validation, escalation

This structure prevents brittle “mega-rules” while maintaining high recall.

---

## Behaviour Before Tools

Detections do **not** target individual tools (Mimikatz, PsExec, etc.).

Instead, I model:
- behaviours that cannot be avoided
- telemetry surfaces attackers must touch
- execution models that persist across campaigns

This makes the hunts resilient to:
- polymorphism
- signed binary abuse
- LOLBins
- fileless and in-memory tradecraft

---

## Attack-Chain-First Design

All rules are derived from **complete attack ecosystems**, not isolated events.

Covered chains include:
Recon → Initial Access → Execution → Persistence → Privilege Escalation  
Credential Access → Lateral Movement → C2 → Exfiltration

Rules are deliberately **split** when:
- execution differs (process vs fileless)
- telemetry cost differs
- tuning domains differ (servers, workstations, admin tooling)

This avoids fragile correlation and reduces false positives.

---

## Adversary-Informed Threat Modelling

Threat models are based on **real campaigns and generalized tradecraft**, not vendor write-ups.

Examples covered:
- OAuth consent abuse & token replay
- WMI persistence vs fileless execution
- Scheduled tasks and service abuse
- LSASS dumping across multiple execution paths
- Supply-chain attack behaviours (SolarWinds / 3CX-style)
- Low-prevalence and jittered C2 infrastructure

The guiding question is always:

> *“How would I execute this quietly in a real enterprise?”*

---

## Scoring & Noise Control

Noise is treated as an **engineering defect**, not an analyst problem.

Rules use:
- prevalence and rarity
- trust boundaries (parent/child lineage)
- path legitimacy
- signing and publisher context
- temporal correlation
- host criticality

Rarity is used to **prioritise**, never to trigger.

---

## Analyst-First Output

Every composite rule includes **Hunter Directives** designed for real SOC use:

- why the alert fired
- what to pivot on next
- common benign explanations
- escalation thresholds
- response guidance

These are written to be readable **during an incident**, not in a slide deck.

# Ala Dabat — Senior Threat Detection & Threat Hunting (Microsoft Sentinel / MDE)

## Overview

I build **production-grade behavioural detection logic** for modern enterprise attack chains.

My work focuses on:

- **Threat hunting that scales**
- **Composite detections that suppress noise**
- **Baseline truth → Reinforcement → Confidence scoring**
- **SOC-ready outputs with embedded analyst directives**

This is not IOC spam or shallow allowlists.

This is **attack-architecture-first detection engineering**, built for real environments.

---

## What I Deliver (Immediately)

### ✅ Production-Ready Composite Detections
Rules designed to survive:

- attacker tradecraft evolution  
- living-off-the-land abuse  
- enterprise background noise  
- hybrid cloud + endpoint complexity  

Each detection includes:

- Minimum Truth anchor  
- Reinforcement joins  
- Org prevalence scoring  
- Noise suppression gates  
- MITRE alignment  
- Analyst-facing HuntingDirectives  

---

## Detection Engineering Framework (Core Philosophy)

### 1. Minimum Truth (Baseline Anchor)
Every rule begins with a single unavoidable behavioural event:

- Registry persistence write  
- Service execution by `services.exe`  
- OAuth consent grant  
- Named pipe C2 deviation  
- TaskCache artefact creation  

This prevents brittle “string matching” logic.

---

### 2. Reinforcement (Convergence Layer)
Signals become high-confidence only when they converge:

- suspicious execution + inbound SMB  
- autorun write + dangerous primitive  
- task execution + TaskCache artefact  
- named pipe + service creation correlation  

Reinforcement does **not redefine truth** — it strengthens it.

---

### 3. Noise Suppression (Enterprise Reality)
Rules are designed for operational environments:

- Safe vendor + safe path suppression  
- Installer/updater suppression  
- Baseline process exclusions  
- Org prevalence rarity weighting  

Noise is controlled structurally, not through endless allowlists.

---

### 4. Confidence Scoring (Prioritisation)
Every hunt outputs a severity-weighted score:

- Rare behaviour = higher priority  
- Wide prevalence = likely admin/tooling  
- Converged execution chains = critical  

Scoring is used as a **triage multiplier**, not a trigger.

---

### 5. SOC-Ready Analyst Directives
Each rule includes embedded guidance:

- what this likely represents  
- immediate pivots  
- containment priorities  
- blast radius expansion logic  

Detection is incomplete without analyst action.

---

## Current Coverage (Tier-1 Enterprise Attack Ecosystems)

| Ecosystem | Minimum Truth Sensor | Status | Maturity |
|----------|----------------------|--------|----------|
| Registry Persistence (Autoruns) | Run/RunOnce ValueSet | ✅ Tested | HIGH |
| Registry Hijacks (COM/IFEO/AppInit) | Execution Flow Interception | ⚠️ Partial | MED |
| Scheduled Tasks (CLI) | `schtasks.exe /create` Truth | ✅ Tested | HIGH |
| Scheduled Tasks (Silent TaskCache) | TaskCache Registry Truth | ⚠️ Tuned | MED |
| SMB + Service Lateral Movement | `services.exe` spawn + SMB inbound | ✅ Empire Validated | HIGH |
| SMB + Scheduled Task Execution (Cousin Rule) | `svchost(Schedule)` spawn + artefacts | ⚠️ POC | MED |
| Credential Access (LSASS) | Dump primitives / access truth | ⚠️ In Progress | MED |
| NTDS / SAM Extraction | Hive/NTDS interaction truth | ⚠️ Partial | MED |
| OAuth Consent Abuse | Scope grant + baseline deviation | ✅ Strong | HIGH |
| Named Pipe C2 + Lateral Correlation | Pipe rarity + SMB + service convergence | ⚠️ Advanced POC | MED |

---

## Repository Structure

### ✅ Production Composite Rules
**Copy-paste deployable hunts**

- `Production-READY-Composite-Threat-Hunting-Rules/`

### 🧪 Attack Ecosystem POCs
Experimental chains parked for expansion:

- `Attack-Ecosystems-and-POC/`

### 📐 Threat Modelling + SOP Logic
Behaviour-first engineering documentation:

- `THREAT-MODELLING-SOP-Behavioural-Patch-Resistant-TTPs-/`

---

## Example Rule Output (SOC-Ready)

A composite hunt does not just alert — it explains:

- Attack class  
- Execution chain  
- Confidence level  
- Analyst next actions  

Example directive:

> CRITICAL: SMB lateral movement via service execution.  
> Validate service binary path, pivot source IP, scope for PsExec/Impacket tooling across fleet.

---

## Why This Matters

Most SOC environments suffer from:

- shallow IOC rules  
- noisy impossible-travel alerts  
- over-allowlisting  
- low-fidelity detections that don’t survive real attacker behaviour  

My focus is building:

> **Behavioural truth-based detection systems that scale.**

---

## Roles I Align With

- Senior Threat Hunter (Microsoft Sentinel / Defender)
- Detection Engineer (KQL + behavioural composites)
- SOC Specialist (Advanced Proactive Detection)
- Threat Intelligence → Detection Translation

---

## Contact / Availability

UK-based. Immediately available for:

- Threat hunting delivery
- Detection rule engineering
- Sentinel/MDE tuning + program uplift
- Hybrid enterprise attack coverage

---

**This work is organic, tested, and built from first principles.**  
It is designed to function in real SOC environments — not in theory.

---

## Contact

**GitHub:** https://github.com/azdabat  
**Email:** azdabat193@gmail.com  
**Location:** United Kingdom  

<p align="center"><i>
“Translating adversary behaviour into measurable defensive depth.”
</i></p>
