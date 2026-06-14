# SIFT-F4S - AI Assisted DFIR Investigation Platform

## Overview

SIFT-F4S (Security Investigation & Forensics Toolkit - Forensics for Security) is an AI-assisted Digital Forensics and Incident Response (DFIR) platform designed to automate the initial triage and analysis of forensic artifacts.

The project combines traditional forensic tools with Large Language Models (LLMs) to generate structured investigation reports and accelerate analyst decision-making.

The objective is not to replace forensic analysts but to augment their capabilities through automated evidence processing, artifact correlation, IOC extraction, and AI-generated reporting.

---

## Project Goals

### Primary Objective

Provide a unified investigation workflow capable of:

* Collecting forensic evidence
* Automatically identifying artifact types
* Executing specialized forensic tools
* Correlating findings
* Generating investigation reports
* Assisting analysts with AI-driven interpretation

### Target Use Cases

* Incident Response
* Malware Investigation
* Digital Forensics
* SOC Operations
* DFIR Training
* Cybersecurity Competitions and Hackathons

---

# System Architecture

```text
                    +------------------+
                    |     Evidence     |
                    | Files / Folders  |
                    +--------+---------+
                             |
                             v

                    +------------------+
                    |    Agent Layer   |
                    |    agent.py      |
                    +--------+---------+
                             |
                             v

                    +------------------+
                    |   Orchestrator   |
                    | orchestrator.py  |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
         v                   v                   v

   +-----------+      +------------+      +------------+
   |   YARA    |      | Volatility |      | Other DFIR |
   | Detection |      |  Analysis  |      |  Modules   |
   +-----------+      +------------+      +------------+

                             |
                             v

                    +------------------+
                    | Findings Engine  |
                    +--------+---------+
                             |
                             v

                    +------------------+
                    | Gemini AI Layer  |
                    +--------+---------+
                             |
                             v

                    +------------------+
                    | Generated Report |
                    | report.md        |
                    +------------------+
```

---

# Repository Structure

```text
sift-f4s/
│
├── agent.py
├── orchestrator.py
├── build2.py
├── run.sh
│
├── sentinel_rules.yar
│
├── uploads/
│
├── reports/
│   └── report.md
│
├── requirements.txt
```

---

# Component Description

## agent.py

Main AI agent.

Responsibilities:

* Launch investigation workflow
* Execute orchestrator pipeline
* Send findings to Gemini
* Generate final forensic report
* Save report into reports/report.md

Input:

```text
Evidence Path
```

Output:

```text
Markdown Forensic Report
```

---

## orchestrator.py

Core investigation engine.

Responsibilities:

* Evidence processing
* Tool orchestration
* Metadata extraction
* Artifact classification
* Findings aggregation

Current supported evidence types:

| Artifact       | Status    |
| -------------- | --------- |
| Memory Dumps   | Supported |
| Disk Images    | Supported |
| Prefetch Files | Supported |
| PCAP Files     | Supported |
| Generic Files  | Supported |

---

## build2.py

MCP server implementation.

Responsibilities:

* Expose forensic tools
* Handle tool requests
* Execute DFIR operations
* Return structured results

---

## sentinel_rules.yar

Custom detection rules.

Current detections include:

### Webshell Indicators

* eval(base64_decode)
* shell_exec
* p0wny-shell
* suspicious PHP patterns

### Privilege Escalation Indicators

* GTFOBins patterns
* APT::Update::Pre-Invoke abuse
* suspicious shell execution traces

---

## run.sh

System launcher.

Responsibilities:

* Environment preparation
* Dependency verification
* Gemini API validation
* MCP server startup
* Agent execution
* Graceful shutdown

Launch command:

```bash
./run.sh <evidence_path>
```

Example:

```bash
./run.sh uploads/img.dd
```

---

# Investigation Workflow

## Step 1

Evidence collection

Examples:

```text
memory.raw
memory.dmp
disk.E01
disk.dd
capture.pcap
sample.exe
```

## Step 2

Artifact classification

The orchestrator identifies the evidence type.

## Step 3

Tool execution

Appropriate forensic tools are launched.

## Step 4

Findings aggregation

All outputs are normalized into a structured format.

## Step 5

AI interpretation

Gemini receives the findings and produces:

* Executive Summary
* Technical Findings
* IOC Extraction
* Recommendations
* Conclusion

## Step 6

Report generation

Output:

```text
reports/report.md
```

---

# Technologies Used

## Artificial Intelligence

* Google Gemini 2.5 Flash Lite

## Programming Language

* Python 3.12

## DFIR Tools

### Volatility 3

Purpose:

* Memory analysis
* Process enumeration
* Kernel artifact analysis

### YARA

Purpose:

* Malware detection
* IOC identification
* Threat hunting

### FastMCP

Purpose:

* Tool orchestration
* Modular DFIR architecture

---

# Current Features

### Automated Evidence Processing

* File identification
* Metadata extraction

### Malware Detection

* YARA scanning

### Memory Analysis

* Volatility integration

### AI Reporting

* Automated forensic reports

### Modular Architecture

* MCP-based tool integration

---

# Known Limitations

### Volatility Symbol Resolution

Some Windows memory images may require additional symbol configuration.

### IOC Correlation

IOC extraction is currently limited and under development.

### Graphical User Interface

Not yet implemented.

---

# Planned Improvements

## User Interface

Planned GUI features:

* Evidence upload
* Investigation dashboard
* IOC viewer
* Case management
* Report export

Recommended technologies:

* Streamlit
* Flask
* FastAPI + React
* Electron

## Advanced DFIR Features

* IOC extraction engine
* Timeline generation
* Threat scoring
* MITRE ATT&CK mapping
* Sigma integration
* Multi-evidence correlation

## Reporting

* PDF export
* DOCX export
* Executive dashboard

---

# Example Usage

```bash
./run.sh uploads/
```

Expected workflow:

```text
Evidence
    ↓
Orchestrator
    ↓
YARA
    ↓
Volatility
    ↓
Findings
    ↓
Gemini
    ↓
report.md
```

---

# Future Developer Notes

If you are implementing the graphical interface:

Do not modify:

* forensic modules
* MCP tools
* YARA engine
* Volatility integration

Use:

```python
run_pipeline()
```

or

```python
ForensicOrchestrator().investigate()
```

as the backend API layer.

The GUI should only act as a frontend consuming investigation results.

This separation ensures maintainability and scalability.

---

# Authors

Project Lead

Olivier Fiabi (Lynxxo_ven)

Cybersecurity & Cybercrime Student
ESA Togo

Project Context

AI-Assisted Digital Forensics and Incident Response Platform

2026
