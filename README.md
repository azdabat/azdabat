<p align="center">
  <img src="https://static.vecteezy.com/system/resources/previews/043/410/734/non_2x/concept-of-private-key-or-cyber-security-graphic-of-electronic-pattern-texured-key-with-futuristic-element-vector.jpg" width="650">
</p>

# ATTRIBUTION-NONCOMMERCIAL-SHAREALIKE 4.0 INTERNATIONAL (CC BY-NC-SA 4.0)

Copyright (c) 2026 Ala Dabat. All Rights Reserved.

This work (including all KQL queries, detection logic, documentation, and the "Minimum Truth" Framework architecture) is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.

## You are free to:
* **Share** — copy and redistribute the material in any medium or format.
* **Adapt** — remix, transform, and build upon the material.

## Under the following terms:
* **Attribution** — You must give appropriate credit to **Ala Dabat**, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **NonCommercial** — You may **NOT** use the material for commercial purposes (e.g., selling these rules, including them in a paid product, or putting them behind a paywall).
* **ShareAlike** — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

---
**View the full Legal Code here:** https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

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

---

## Validation & Testing

Validation is performed using:

- **Atomic Red Team** (behaviour coverage)
- **ADX Docker** (KQL logic and scoring validation)
- **Synthetic attack simulation** (edge-case testing)

Without live tenant telemetry, I validate:
- correctness of attack truth
- telemetry availability
- logical noise suppression
- documented blind spots

Final tuning is always environment-specific.

---

## Repository Structure

| Path | Description |
|-----|-------------|
| `/Composite-Threat-Hunting-Rules/` | Production-safe composite hunts |
| `/Core-Threat-Hunts/` | Lower-noise SOC-ready analytics |
| `/engineering/` | Advanced correlation and research logic |
| `/matrices/` | MITRE mappings and coverage |
| `/docs/` | Methodology, SOPs, IR guidance |
| `/samples/` | Test data and examples |

---

## Intended Audience

- Senior SOC Analysts (L2/L3)
- Threat Hunters
- Detection Engineers
- MDR / IR teams
- Purple teams and red-blue collaboration

This repository prioritises **behavioural depth and operational fidelity** over alert volume.

---

## Guiding Principles

1. Behaviour before signatures  
2. Correlation before alerts  
3. Context over noise  
4. Explicit blind-spot documentation  
5. Engineering depth with hunter agility  

---

## Contact

**GitHub:** https://github.com/azdabat  
**Email:** azdabat193@gmail.com  
**Location:** United Kingdom  

<p align="center"><i>
“Translating adversary behaviour into measurable defensive depth.”
</i></p>
