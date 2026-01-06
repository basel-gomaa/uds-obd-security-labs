# UDS / OBD-II ECU Simulation & Security Testing (ISO-TP over CAN)

This repository contains hands-on automotive cybersecurity labs for UDS (ISO 14229) and OBD-II over ISO-TP on CAN (SocketCAN/vCAN).

It is designed for educational and research purposes to demonstrate how diagnostic services work, how they can be misused, and how basic defensive mechanisms can mitigate common attacks.

Contributors

-Basel Gomaa (@basel-gomaa)

-Medhat ElEssawy (@MedhatElessawy)

-Mohamed Basta

---

## More Details & Related Repository

For a broader framework view and additional implementation details, please refer to the main project repository by @MedhatElessawy:

https://github.com/MedhatElessawy/Automotive-OBD_II-UDS-Security-Framework

This repository focuses on the practical lab side (ECU simulation + offensive testing), while the related repository provides extended framework components and documentation.

---

## Project Context & Collaboration

This repository represents a hands-on laboratory implementation developed as part of a broader automotive cybersecurity effort.

The core framework and architectural concepts are based on collaborative work with **@MedhatElessawy**, whose main project repository can be found here:  
https://github.com/MedhatElessawy/Automotive-OBD_II-UDS-Security-Framework

This repository focuses specifically on:
- Practical UDS and OBD-II attack simulations
- ECU behavior analysis under diagnostic abuse
- Hands-on offensive and defensive experimentation in a lab environment

Both repositories were developed as part of the same training track and complement each other.

---

## Repository Overview

This lab environment includes:
- A simulated ECU implementing UDS and OBD-II services
- An offensive attack tool demonstrating common diagnostic attacks
- A virtual CAN setup using SocketCAN / vCAN

---

## Components

### 1) ECU Simulator

**File:** `ecu.py`

A Python-based ECU simulator that responds to OBD-II and UDS requests over ISO-TP on CAN.

#### OBD-II Features

- Mode `0x09` (Vehicle Information)
  - VIN (PID `0x02`)
- Mode `0x01` (Live Data)
  - Example PIDs such as RPM and vehicle speed

#### UDS Features

- `0x10` – Diagnostic Session Control (Default / Extended / Programming)
- `0x27` – SecurityAccess (seed/key mechanism)
- `0x11` – ECU Reset (protected by SecurityAccess)
- `0x22` – ReadDataByIdentifier (VIN, Serial Number, Program Image)
- `0x2E` – WriteDataByIdentifier (Program image persistence)
- `0x31` – RoutineControl (Self-test and checksum routines)
- `0x3E` – TesterPresent with S3 session timeout handling

#### Security / Hardening Options

The ECU includes optional defensive behaviors (configurable via code flags), such as:
- Limited wrong-key attempts with lockout window
- Optional session-token requirement to mitigate MITM-style attacks
- Protected vs unprotected seed-to-key algorithms (lab toggles)

---

### 2) Attack Tool (Offensive Lab)

**File:** `attack.py`

A menu-driven attacker tool that demonstrates common offensive techniques against UDS and OBD-II diagnostic services over ISO-TP.

#### Implemented Capabilities

- UDS DID / RID Enumeration
  - Enumerates accessible Data Identifiers (`0x22`)
  - Enumerates Routine Identifiers (`0x31`) and blocked routines
- SecurityAccess brute-force (educational)
  - Attempts keys within a predefined range
- MITM-style session manipulation
  - Forces session transitions after successful SecurityAccess
  - Keeps S3 session alive using TesterPresent
- Seed/Key algorithm guessing
  - Attempts to infer simple seed-to-key relationships (add/sub/xor/mul)
- Reset flooding / diagnostic DoS simulation
- OBD PID Enumeration and Replay
  - Enumerates supported PIDs
  - Sniffs and replays ECU responses (lab demonstration)

---

## Technology Stack

- Python
- SocketCAN / vCAN
- `python-can`
- `isotp` (ISO-TP transport layer)
- Linux (Kali / Ubuntu)

---

## How to Run (vCAN Lab)

```bash
# 1) Create virtual CAN interface
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# 2) Start the ECU (Terminal 1)
python3 ecu.py



# 3) Run the attacker tool (Terminal 2)
python3 attack.py
