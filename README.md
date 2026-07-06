# PFCP Session Manipulation Challenges — 5G Capture the Flag

**Auto-scored fuzzing and resource-exhaustion CTF challenges targeting the PFCP N4 interface in a 5G core network.** Built on Free5GC + UERANSIM + CTFd, with automated judges written in Scapy. Research published at IEEE.

[![Python](https://img.shields.io/badge/Python-Scapy-blue)]()
[![IEEE](https://img.shields.io/badge/Published-IEEE-b31b1b)]()
[![5G Core](https://img.shields.io/badge/5G%20Core-Free5GC-orange)]()

## Overview

The 5G core network separates the control plane and user plane, connected via the **Packet Forwarding Control Protocol (PFCP)** over the **N4 interface** between the Session Management Function (SMF) and User Plane Function (UPF), as defined in 3GPP TS 29.244. This separation is powerful architecturally, but it also concentrates a lot of trust in a single, often under-protected interface — session hijacking, message tampering, and service disruption all become possible if N4 is exposed or under-isolated.

This repo packages that vulnerability into two hands-on, auto-scored CTF challenges:

- **[Resource Exhaustion](challenges/resource_exhaustion)** — a volumetric flooding attack that overwhelms the UPF with forged PFCP session establishment requests
- **[Session Deletion](challenges/session_deletion)** — a targeted attack that guesses a session's 64-bit SEID to disrupt it directly

Both challenges are scored automatically: a lightweight judge daemon sniffs the N4 interface, detects a successful attack in real time, and submits the solve to the CTFd platform on the player's behalf — no manual grading required.

## How auto-scoring works

Each challenge is paired with a judge process with visibility into the N4 interface:

1. At game setup, each judge receives a challenge ID and a secret flag
2. Attackers embed their CTFd API token into their forged PFCP packet payloads
3. The judge — built with [Scapy](https://scapy.net/) — sniffs N4 traffic, detects the attack condition (e.g. request rate over threshold, or a valid deletion request for the target SEID), extracts the token, and submits the solve directly to the CTFd API
4. This closes the loop between a live attack against real 5G core software and the CTF scoreboard, without a human in the middle

This builds on prior GTP packet-injection judge work (published at IEEE WF-IoT 2024) by extending auto-scoring to flooding and fuzzing-style attacks — a first for CTF-style network challenges.

## Architecture

```
 UERANSIM (UE/gNB)  ──GTP-U tunnel──►  Free5GC UPF  ◄──PFCP (N4, UDP/8805)──►  Free5GC SMF
                                            │
                                            │  sniffs N4
                                            ▼
                                    Judge (Scapy daemon)
                                            │
                                            ▼
                                     CTFd API (solve)
```

Poor traffic isolation at the UPF allows PFCP packets forged from the simulated UE/RAN side to reach the N4 interface — this is the vulnerability both challenges exploit.

## Repo structure

```
challenges/
├── resource_exhaustion/   # Flooding attack on PFCP session establishment
│   ├── judge.py           # Detects flood, extracts token, submits solve
│   └── attack.py          # Sample attack (provided for verification)
└── session_deletion/      # Targeted SEID-guessing deletion attack
    └── README.md          # Shares judge/attack pattern with resource_exhaustion
```

## Tech stack

`Free5GC` · `UERANSIM` · `CTFd` · `Python` · `Scapy` · `3GPP TS 29.244 (PFCP)`

## Research

This work builds on and extends published research on 5G-focused CTF game design:

- J. Melzer, A. Shafo, Z. Zhao, P. P. Wang, W. Fenwick, W. Almuhtadi, *"Developing 'Capture the Flag' for 5G IoT Cyber Security Training,"* IEEE WF-IoT 2024. DOI: [10.1109/wf-iot62078.2024.10811259](https://doi.org/10.1109/wf-iot62078.2024.10811259)

*(Add citation details for the follow-up paper covering these specific fuzzing/resource-exhaustion challenges once published/indexed.)*

## Acknowledgements

Developed at **Algonquin College** in collaboration with **TELUS**, with funding support from **NSERC** and **Mitacs**.

- Amina Shafo — Student Researcher, Algonquin College
- Zhichuan Zhao — Student Researcher, Algonquin College
- Jordan Melzer — Sr. Engineer, Broadband Access, TELUS
- Wynn Fenwick — Sr. Consultant, Cyber Security Architecture, TELUS
- Wahab Almuhtadi — Professor, Algonquin College

## Disclosure

These challenges are designed for educational and research use in controlled lab environments only. They demonstrate real vulnerabilities in exposed 5G N4 interfaces to motivate proper interface isolation and encourage standardization of authenticated transport for 5G core network interfaces.

## License

*(Add a license — MIT is a reasonable default for educational/research code, unless your funding/collaboration agreement specifies otherwise.)*
