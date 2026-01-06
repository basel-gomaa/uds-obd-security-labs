UDS / OBD-II ECU Simulation & Security Testing (ISO-TP over CAN)

This repository contains hands-on automotive cybersecurity labs for UDS (ISO 14229) and OBD-II over
ISO-TP on CAN (SocketCAN/vCAN).

It is designed for educational and research purposes to demonstrate how diagnostic services work, how they can be misused, and how basic defensive mechanisms can mitigate common attacks.

⚠️ Educational / lab use only.
Do NOT use this project on real vehicles or production systems.

Repository Overview

This lab environment includes:

A simulated ECU implementing UDS and OBD-II services

An offensive attack tool demonstrating common diagnostic attacks

A virtual CAN setup using SocketCAN / vCAN

Components
1) ECU Simulator

File: ecu.py

A Python-based ECU simulator that responds to OBD-II and UDS requests over ISO-TP on CAN.

OBD-II Features

Mode 0x09 (Vehicle Information)

VIN (PID 0x02)

Mode 0x01 (Live Data)

Example PIDs such as RPM and vehicle speed

UDS Features

0x10 – Diagnostic Session Control
(Default / Extended / Programming)

0x27 – SecurityAccess (seed/key mechanism)

0x11 – ECU Reset (protected by SecurityAccess)

0x22 – ReadDataByIdentifier
(VIN, Serial Number, Program Image)

0x2E – WriteDataByIdentifier
(Program image persistence)

0x31 – RoutineControl
(Self-test and checksum routines)

0x3E – TesterPresent with S3 session timeout handling

Security / Hardening Options

The ECU includes optional defensive behaviors (configurable via code flags), such as:

Limited wrong-key attempts with lockout window

Optional session-token requirement to mitigate MITM-style attacks

Protected vs unprotected seed-to-key algorithms (lab toggles)

2) Attack Tool (Offensive Lab)

File: attack.py

A menu-driven attacker tool that demonstrates common offensive techniques against UDS and OBD-II diagnostic services over ISO-TP.

Implemented Capabilities

UDS DID / RID Enumeration

Enumerates accessible Data Identifiers (0x22)

Enumerates Routine Identifiers (0x31) and blocked routines

SecurityAccess brute-force (educational)

Attempts keys within a predefined range

MITM-style session manipulation

Forces session transitions after successful SecurityAccess

Keeps S3 session alive using TesterPresent

Seed/Key algorithm guessing

Attempts to infer simple seed-to-key relationships (add/sub/xor/mul)

Reset flooding / diagnostic DoS simulation

OBD PID Enumeration and Replay

Enumerates supported PIDs

Sniffs and replays ECU responses (lab demonstration)

Technology Stack

Python

SocketCAN / vCAN

python-can

isotp (ISO-TP transport layer)

Linux (Kali / Ubuntu)

How to Run (vCAN Lab)
# 1) Create virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 2) Start the ECU (Terminal 1)
python3 ecu.py

# 3) Run the attacker tool (Terminal 2)
python3 attack.py

What This Lab Demonstrates

Diagnostic attack surface of UDS and OBD-II over CAN

Enumeration of ECU capabilities (DIDs, RIDs, PIDs)

Weaknesses of unauthenticated diagnostic services

Session-based authorization and S3 timeout behavior

Brute-force, replay, and flooding risks

Effectiveness of basic defensive mechanisms

Importance of correct Negative Response Codes (NRCs)

Suggested Repository Name

For a clean, recruiter-friendly project name:

uds-obd-security-labs

Or a broader, future-proof option:

automotive-diagnostics-security-labs
