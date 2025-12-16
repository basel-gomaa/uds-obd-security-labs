# UDS / OBD-II ECU Simulation & Security Testing (ISO-TP over CAN)

This repository contains hands-on automotive cybersecurity labs for **UDS (ISO 14229)** and **OBD-II** over
**ISO-TP on CAN (SocketCAN/vCAN)**, including:
- A simulated ECU that implements common diagnostic services and session logic
- An attacker tool implementing multiple offensive test/attack scenarios
- A UDS test suite (automated test cases) with logging

> ⚠️ Educational / lab use only. Do **NOT** use on real vehicles or production systems.

---

## Components

### 1) ECU Simulator
**File:** `ecu.py`

Implements a lab ECU that responds to OBD-II and UDS requests over ISO-TP on CAN.

**OBD-II features**
- Mode **0x09** (Vehicle Information): VIN (PID 0x02)
- Mode **0x01** (Live Data): example PIDs (RPM, Speed, etc. depending on implementation)

**UDS features**
- **0x10** Diagnostic Session Control (Default / Extended / Programming)
- **0x27** SecurityAccess (seed/key) with optional protections
- **0x11** ECUReset (protected by SecurityAccess)
- **0x22** ReadDataByIdentifier (VIN / Serial / Program image)
- **0x2E** WriteDataByIdentifier (program image persistence)
- **0x31** RoutineControl (self-test + checksum routine example)
- **0x3E** TesterPresent + S3 session timeout handling

**Security / hardening options**
The ECU includes optional defensive behaviors (controlled by flags in the code), such as:
- Limited wrong-key attempts + lockout window
- Optional MITM/session-token requirement for session transitions
- Protected vs unprotected seed->key mode (lab toggles)

---

### 2) Attack Tool (Offensive Lab)
**File:** `attack.py`

Menu-driven attacker for UDS/OBD over ISO-TP that demonstrates common offensive techniques against diagnostic services.

**Implemented capabilities (lab-grade)**
- **UDS DID/RID enumeration**
  - Scans DIDs using **0x22** and reports positive responses
  - Scans RIDs using **0x31** and reports accessible routines / blocked responses
- **Seed-based brute force (SecurityAccess)**
  - Attempts keys within a defined range for **0x27** (educational demonstration)
- **MITM-style session manipulation**
  - Watches for successful SecurityAccess then forces session transitions + keeps S3 alive
- **Seed/key algorithm guessing (reverse engineering demo)**
  - Tries simple relationships (add/sub/xor/mul) on observed seed/key pairs
- **Reset spamming / DoS-like diagnostic flooding**
- **OBD PID enumeration + replay**
  - Enumerates supported PIDs for selected modes
  - Sniffs traffic and replays ECU responses (lab demonstration)

---

### 3) Automated UDS Test Suite
**File:** `UDS_TestCases - Copy.py`

UDS tester that includes a **minimal ISO-TP implementation** and a set of test cases that validate:
- SecurityAccess flows (seed request, correct/wrong key handling)
- Session entry rules (denied without auth, allowed with auth)
- S3 timeout behavior and TesterPresent handling
- DID access control (VIN/Serial restrictions by session)
- Routine control behavior (allowed/denied by session)
- Handling of malformed / unsupported requests

Outputs a JSON report (`uds_test_log.json`) with PASS/FAIL results.

---

## Technology Stack
- **Python**
- **SocketCAN / vCAN**
- **python-can**
- **isotp** (python ISO-TP transport layer)
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

# 3) Run attacker menu (Terminal 2)
python3 attack.py

# 4) Run automated UDS test cases (Terminal 3)
python3 "UDS_TestCases - Copy.py" --bus vcan0 --tx-id 0x7E0 --rx-id 0x7E8
```

---

## What This Lab Demonstrates (Cybersecurity Concepts)
- Diagnostic attack surface of UDS/OBD on CAN
- Enumeration of ECU functionality (DIDs/RIDs/PIDs)
- Lack of authentication in classic diagnostic stacks (unless enforced)
- Session-based authorization and S3 timeout behavior
- Brute-force and replay risks (and how basic defenses mitigate them)
- Importance of correct negative response handling (NRCs)

---

## Suggested Repo Name
If you want a clean, recruiter-friendly repo name:
- `uds-obd-security-labs`
or (broader, future-proof):
- `automotive-diagnostics-security-labs`

---

## Disclaimer
This project is for educational and research purposes only.
Do not use it to attack systems you do not own or have explicit permission to test.
