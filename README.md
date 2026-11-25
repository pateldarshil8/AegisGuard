# AegisGuard AI

Endpoint security and system health suite for Windows.

*Status: early development (v0.1 scaffold: health, scanner, firewall audit, reports, basic UI).*

## Overview

AegisGuard AI brings endpoint protection and system health monitoring into one desktop application, with clear, plain-language findings and guided fixes.

## Planned Features

- **Smart Firewall**: monitors network connections and flags suspicious traffic.
- **Malware Scanner**: Defender-style scanning of files and processes.
- **Vulnerability and Bug Fixer**: detects misconfigurations and common system issues and applies guided fixes.
- **Report Generator**: produces readable security and system health reports (rule-based, no AI/cloud dependency).

## Tech Stack

- Python backend
- Desktop UI (Tkinter for now)
- Target platform: Windows 10/11

## Roadmap

- [ ] Define architecture and module boundaries
- [ ] Build core scanner engine
- [ ] Implement firewall monitoring
- [ ] Add vulnerability detection and fixer
- [ ] Add report generation
- [ ] Build desktop UI

## Run (Windows)

```
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
aegisguard full
aegisguard ui
pytest
```

Firewall changes and fixes will always require explicit user approval; v0.1 is read-only.

## Author

Darshil Patel - [GitHub](https://github.com/pateldarshil8)
