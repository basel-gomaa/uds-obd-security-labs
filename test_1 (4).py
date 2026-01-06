# tester_isotp.py  (no size byte, ISO-TP handles length)
import can
import isotp
import time
from isotp import CanMessage
from typing import Dict, Tuple, Optional
from collections import deque
import keyboard  # NOTE: on Linux this requires root

# ---------------- OBD-II IDs ----------------
functional_address  = 0x7DF
engine_ecu_physical = 0x7E0
body_ecu_physical   = 0x7E0
engine_ecu          = 0x7E8   # engine response id
body_ecu            = 0x7E8   # body response id

# ---------------- UDS Service IDs ----------------
DIAGNOSTIC_SESSION_CONTROL      = 0x10
SECURITY_ACCESS                 = 0x27
TESTER_PRESENT                  = 0x3E
READ_DATA_BY_IDENTIFIER         = 0x22
WRITE_DATA_BY_IDENTIFIER        = 0x2E
ROUTINE_CONTROL                 = 0x31

DEFAULT_SESSION                 = 0x100
PROGRAMMING_SESSION             = 0x200
EXTENDED_SESSION                = 0x300

bus = can.Bus(channel='vcan0', interface='socketcan')

def txfn(iso_msg: isotp.CanMessage) -> None:
    msg = can.Message(
        arbitration_id=iso_msg.arbitration_id,
        data=iso_msg.data,
        dlc=iso_msg.dlc,
        is_extended_id=False
    )
    bus.send(msg)

DEFAULT_PARAMS = {
    "tx_padding": 0x55,
    "tx_data_length": 8,
    "tx_data_min_length": 8,
}

_rx_queues: Dict[int, deque] = {
    body_ecu: deque(),
    engine_ecu: deque(),
}

def pump_bus(timeout: float = 0.0):
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
        pump_bus(timeout=0.01)
        stack.process()
        time.sleep(stack.sleep_time())

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

def Hex_to_Int(s) -> int:
    if isinstance(s, int):
        return s
    s = str(s).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)

OBD_MODES = {
    0x01: "Request Live Data",
    0x02: "Request Freeze Frames",
    0x03: "Request Stored Trouble Codes",
    0x04: "Clear/Reset Stored Emissions Related Data",
    0x05: "Request Oxygen Sensors Test Results",
    0x06: "Request On-Board System Tests Results",
    0x07: "Request Pending Trouble Codes",
    0x08: "Request Control of On-Board Systems",
    0x09: "Request Vehicle Information",
    0x0A: "Request Permanent Trouble Codes",
}
VALID_MODES = set(OBD_MODES.keys())

def Mode_Check(mode_hex: str) -> int:
    mode = Hex_to_Int(mode_hex)
    return 1 if mode in VALID_MODES else 0

def OBD_Frame(id_hex: str, mode_hex: str, pid_hex, user_data: list[int] = None):
    if Mode_Check(mode_hex) == 0:
        print("[ERROR] Invalid Mode. Restart function with correct Mode.")
        return None

    if user_data is None:
        user_data = []

    can_id = Hex_to_Int(id_hex)
    mode   = Hex_to_Int(mode_hex)

    if isinstance(pid_hex, list):
        pids = pid_hex
    else:
        pids = [Hex_to_Int(pid_hex)]

    # no-size for all modes now
    frame = bytes([mode] + pids + user_data)

    frame_Flag = 1
    return can_id, frame, frame_Flag

def get_hex_input(prompt: str) -> str:
    x = input(prompt).strip()
    try:
        Hex_to_Int(x)
        return x
    except:
        print("Invalid hex. Enter again.")
        return get_hex_input(prompt)

def get_pid_list() -> list[int]:
    raw = input("Enter PID(s) (0C 0D 05 or 0C0D05): ").strip()
    if raw == "":
        return []

    if " " in raw:
        parts = raw.split()
    else:
        if len(raw) % 2 != 0:
            print("Invalid PID list format.")
            return get_pid_list()
        parts = [raw[i:i+2] for i in range(0, len(raw), 2)]

    out = []
    for p in parts:
        try:
            out.append(Hex_to_Int(p))
        except:
            print(f"Invalid PID: {p}")
            return get_pid_list()
    return out

def get_user_data_list() -> list[int]:
    raw = input("Enter user data or press Enter: ").strip()
    if raw == "":
        return []

    if " " in raw:
        parts = raw.split()
    else:
        if len(raw) % 2 != 0:
            print("Invalid format: continuous hex must have even length.")
            return get_user_data_list()
        parts = [raw[i:i+2] for i in range(0, len(raw), 2)]

    out = []
    for p in parts:
        try:
            out.append(Hex_to_Int(p))
        except:
            print(f"Invalid byte: {p}")
            return get_user_data_list()

    return out

def bytes_to_vin(byte_list: list[int]) -> str:
    return ''.join(chr(b) for b in byte_list)

def OBD():
    print("=== Build OBD Frame ===")

    id_hex   = get_hex_input("Enter CAN ID (hex): ")
    mode_hex = get_hex_input("Enter Mode   (hex): ")

    if Hex_to_Int(mode_hex) == 0x01:
        pid_list = get_pid_list()
        if not pid_list:
            print("No PIDs entered.")
            return
        pid_hex = pid_list
    else:
        pid_hex = get_hex_input("Enter PID    (hex): ")

    user_data = get_user_data_list()

    result = OBD_Frame(id_hex, mode_hex, pid_hex, user_data)
    if result is None:
        return

    Id, frame, flag = result
    mode = frame[0]   # no-size: mode at index 0

    if mode == 0x09:
        if Id == functional_address:
            req_txid = functional_address
        elif Id == body_ecu_physical:
            req_txid = body_ecu_physical
        else:
            print("[ERROR] Mode 09 only allows ID 0x7DF or 0x7E1.")
            time.sleep(1.0)
            return

        print(f"[TESTER] Sending Request: 0x{req_txid:03X} , {' '.join(f'{b:02X}' for b in frame)}")
        ISOTP_SEND(frame, txid=req_txid, rxid=body_ecu)

        response = ISOTP_RECEIVE(txid=req_txid, rxid=body_ecu, timeout=5.0)

        if response is None:
            print("[Tester] received response: None")
        else:
            if response[0] == 0x7F:
                print("Service not supported in active session")
            elif response[0] == 0x12:
                print("Sub function not supported")
            else:
                vin_string = bytes_to_vin(list(response))
                print(f"[Tester] Body response: 0x{body_ecu:03X} , {' '.join(f'{b:02X}' for b in response)}")
                print(f"[Tester] Vin number is : {vin_string}")

    elif mode == 0x01:
        if Id not in (functional_address, engine_ecu_physical):
            time.sleep(1.0)
            return

        print(f"[TESTER] Sending Request: 0x{Id:03X} , {' '.join(f'{b:02X}' for b in frame)}")
        ISOTP_SEND(frame, txid=Id, rxid=engine_ecu)

        window_end = time.time() + 1.0
        replies = []

        while time.time() < window_end:
            resp = ISOTP_RECEIVE(txid=Id, rxid=engine_ecu, timeout=0.2)
            if resp is None:
                continue
            replies.append(resp)

        if not replies:
            print("[Tester] received response: None")
        else:
            for response in replies:
                print(f"[Tester] Engine response: 0x{engine_ecu:03X} , {' '.join(f'{b:02X}' for b in response)}")

                if response[0] == 0x7F:
                    print("Service not supported in active session")
                    continue

                if response[0] != (0x40 + mode):
                    continue

                pid = response[1]
                data = response[2:]

                if pid == 0x0C and len(data) >= 2:
                    A, B = data[0], data[1]
                    rpm = ((A * 256) + B) / 4
                    print(f"[Tester] Received RPM: {rpm}")
                elif pid == 0x0D and len(data) >= 1:
                    speed = data[0]
                    print(f"[Tester] Received Speed: {speed} Km/h")
                else:
                    print(f"[Tester] Received PID {pid:02X}: {' '.join(f'{b:02X}' for b in data)}")

    else:
        print("Mode is not supported")
        return

    time.sleep(1.0)

def get_hex_list(prompt: str) -> list[int]:
    raw = input(prompt).strip()
    if raw == "":
        return []

    # Case 1: user separated bytes with spaces → "10 27 3E"
    if " " in raw:
        parts = raw.split()

    # Case 2: continuous hex string → "10273E"
    else:
        if len(raw) % 2 != 0:
            print("Invalid hex list format.")
            return get_hex_list(prompt)
        parts = [raw[i:i+2] for i in range(0, len(raw), 2)]

    out = []
    for p in parts:
        try:
            out.append(Hex_to_Int(p))
        except:
            print(f"Invalid hex byte: {p}")
            return get_hex_list(prompt)

    return out

# ---------------- UDS Service IDs ----------------
UDS_SERVICES = {
    0x10: "Diagnostic Session Control",
    0x11: "ECU Reset",
    0x22: "Read Data by Identifier",
    0x23: "Read Memory by Address",
    0x27: "Security Access",
    0x28: "Communication Control",
    0x2E: "Write Data by Identifier",
    0x31: "Routine Control",
    0x34: "Request Download",
    0x35: "Request Upload",
    0x36: "Transfer Data",
    0x37: "Request Transfer Exit",
    0x3E: "Tester Present",
}

VALID_UDS = set(UDS_SERVICES.keys())

def UDS_Check(sid: int) -> int:
    return 1 if sid in VALID_UDS else 0

KEY = 0x11223344 # your fixed key

def seed_to_key(seed: bytes) -> bytes:
    # treat seed as big-endian integer (common UDS practice)
    seed_int = int.from_bytes(seed, byteorder="big")
    key_int  = seed_int ^ KEY
    return key_int.to_bytes(len(seed), byteorder="big")

def UDS_SECURITY_ACCESS(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:

    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)

    response = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
    if response and response[0] == (0x27 + 0x40) and response[1] == 0x01:
        seed = response[2:]

        key_bytes = seed_to_key(seed)
        frame = bytes([0x27, 0x02]) + key_bytes
        ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
        resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
        if resp and resp[0] == (0x27 + 0x40) and resp[1] == 0x02:
            print("Security Access Granted")
        elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x35:
            print("Invalid Key")
        elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x33:
            print("Security Access Denied")
    elif response and response[0] == 0x7F:
        print("Incorrect Condition")

def UDS_DIAGNOSTIC_SESSION_CONTROL(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:
    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
    resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
    if resp and resp[0] == 0x50:
        if resp[1] == 0x01:
            print("Default Session is on")
        elif resp[1] == 0x02:
            print("Programming Session is on")
        elif resp[1] == 0x03:
            print("Extended Session is on")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x33:
        print("Security Access Denied")

def UDS_ECU_RESET(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:
    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
    resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
    if resp and resp[0] == 0x51:
        print("ECU Reset is Done.")

def UDS_READ_DATA_BY_IDENTIFIER(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:
    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
    resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
    if resp is None:
        print("[Tester] No response for ReadDataByIdentifier")
        return

    # Positive response should be 0x62 for service 0x22
    if resp[0] == 0x62 and len(resp) >= 3:
        did = (resp[1] << 8) | resp[2]
        data = resp[3:]
        if did == 0xF190:
            vin_string = bytes_to_vin(list(data))
            print(f"[Tester] Vin number is : {vin_string}")
        elif did == 0xF18C:
            serial_string = bytes_to_vin(list(data))
            print(f"[Tester] Serial number is : {serial_string}")

    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x31:
        print("Request Out Of Range (unsupported DID)")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x13:
        print("Incorrect Message Length")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x22:
        print("Conditions Not Correct")

def UDS_WRITE_DATA_BY_IDENTIFIER(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:
    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
    resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)
    if resp is None:
        print("[Tester] No response for WriteDataByIdentifier")
        return

    print(f"[Tester] UDS Write Response: {' '.join(f'{b:02X}' for b in resp)}")
    # Positive response should be 0x6E for service 0x2E
    if resp[0] == 0x6E and len(resp) >= 3:
        did = (resp[1] << 8) | resp[2]
        print(f"[Tester] Write acknowledged for DID 0x{did:04X}")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x31:
        print("Request Out Of Range (unsupported DID)")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x13:
        print("Incorrect Message Length")
    elif resp and resp[0] == 0x7F and resp[1] == frame[0] and resp[2] == 0x33:
        print("Request Not Allowed In This Session")

# ---------------- Routine support (from tester_routines.py) ----------------

# Routine IDs
RID_SELF_TEST = 0x1234
RID_CHECKSUM  = 0x5678

# ANSI colors
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

def pretty_hex(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)

def print_routine_result(rid_placeholder, payload: bytes) -> None:
    """
    Interpret routine result (0x71, subfunc 0x03) as in tester_routines.py
    payload: full positive response bytes
    """
    if len(payload) < 5:
        print("Malformed routine result")
        return

    subfunc = payload[1]
    rid_val = (payload[2] << 8) | payload[3]
    data = payload[4:-1]  # last byte is status
    status = payload[-1]
    print(f"Routine 0x{rid_val:04X} Result (status {status}):")

    if rid_val == RID_SELF_TEST:
        if len(data) >= 3:
            rpm = (data[0] << 8) | data[1]
            speed = data[2]
            rpm_color = GREEN if rpm != 0 else RED
            speed_color = GREEN if speed != 0 else RED
            print(f"  RPM: {rpm_color}{rpm}{RESET}")
            print(f"  Speed: {speed_color}{speed}{RESET}")
        else:
            print("  Invalid self-test data")

    elif rid_val == RID_CHECKSUM:
        if len(data) >= 4:
            crc = int.from_bytes(data[:4], "big")
            color = GREEN if crc != 0 else RED
            print(f"  CRC32: {color}{crc:08X}{RESET}")
        else:
            print("  Invalid checksum data")

    else:
        print("  Unknown routine")

def UDS_ROUTINE_CONTROL(req_txid: int, req_rxid: int, uds_frame: list[int]) -> None:
    """
    Service 0x31: RoutineControl
    Sends uds_frame, waits for one response, and prints it.
    Uses the same interpretation as tester_routines.py for:
     - RID 0x1234 (self test)
     - RID 0x5678 (checksum)
    """
    frame = bytes(uds_frame)
    ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
    resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=5.0)

    if resp is None:
        print("[Tester] No response for RoutineControl")
        return

    # Negative response
    if resp[0] == 0x7F and len(resp) >= 3:
        sid = resp[1]
        nrc = resp[2]
        print(f"⬅ NRC: 7F {sid:02X} {nrc:02X}")
        if len(resp) > 3:
            print("Extra:", pretty_hex(resp[3:]))
        return

    # Positive routine response: 0x71 = 0x31 + 0x40
    if resp[0] == 0x71:
        if len(resp) < 2:
            print("⬅ POS (malformed):", pretty_hex(resp))
            return
        subfunc = resp[1]
        if subfunc == 0x03:
            print_routine_result(0, resp)
        else:
            print("Routine response:", pretty_hex(resp))
        return

    # Other positive response
    print("⬅ POS:", pretty_hex(resp))

# ---------------- TesterPresent hotkey ----------------

# last physical ECU used for UDS (for TesterPresent)
last_tp_txid: Optional[int] = None
last_tp_rxid: Optional[int] = None

def tp_hotkey():
    global last_tp_txid, last_tp_rxid
    # If we don't have a valid physical ECU, do nothing
    if last_tp_txid is None or last_tp_rxid is None:
        return

    frame = bytes([0x3E, 0x00])
    print(f"\n[TESTER] Sending TesterPresent: 0x{last_tp_txid:03X} , {pretty_hex(frame)}")
    ISOTP_SEND(frame, txid=last_tp_txid, rxid=last_tp_rxid)
    resp = ISOTP_RECEIVE(txid=last_tp_txid, rxid=last_tp_rxid, timeout=2.0)
    if resp is not None:
        print(f"[TESTER] TP Response: {pretty_hex(resp)}")
    else:
        print("[TESTER] No TP response")

    # Reprint prompt after hotkey
    print("Enter UDS Frame:  ", end='', flush=True)

keyboard.add_hotkey('ctrl+r', tp_hotkey)

# ---------------- UDS main builder ----------------

def UDS():
    global last_tp_txid, last_tp_rxid

    print("=== Build UDS Frame ===")
    id_hex_str = get_hex_input("Enter CAN ID (hex): ")
    can_id = Hex_to_Int(id_hex_str)
    if can_id != functional_address and can_id != body_ecu_physical and can_id != engine_ecu_physical:
        print("[ERROR] Invalid ID.")
        return None

    while True:
        uds_frame = get_hex_list("Enter UDS Frame:  ")

        print(f"[TESTER] UDS Frame: 0x{can_id:03X} , {' '.join(f'{b:02X}' for b in uds_frame)}")
        if len(uds_frame) == 0:
            print("[ERROR] Empty UDS frame.")
            return None

        if UDS_Check(uds_frame[0]) == 0:
            print("[ERROR] Invalid SID. Restart function with correct SID.")
            return None

        if can_id == functional_address:
            req_txid = functional_address
            req_rxid = None  # functional may get multiple responders
        elif can_id == body_ecu_physical:
            req_txid = body_ecu_physical
            req_rxid = body_ecu
        elif can_id == engine_ecu_physical:
            req_txid = engine_ecu_physical
            req_rxid = engine_ecu
        else:
            print("[ERROR] Unknown CAN ID.")
            return None

        # update last TP destination only when we have a physical ECU
        if req_rxid is not None:
            last_tp_txid = req_txid
            last_tp_rxid = req_rxid

        service = uds_frame[0]
        if service == 0x10:
            if req_rxid is None:
                print("[ERROR] Session control must be sent to a physical ECU.")
                continue
            UDS_DIAGNOSTIC_SESSION_CONTROL(req_txid, req_rxid, uds_frame)
        elif service == 0x27:
            if req_rxid is None:
                print("[ERROR] Security Access must be sent to a physical ECU.")
                continue
            UDS_SECURITY_ACCESS(req_txid, req_rxid, uds_frame)
        elif service == 0x11:
            if req_rxid is None:
                print("[ERROR] ECU Reset must be sent to a physical ECU.")
                continue
            UDS_ECU_RESET(req_txid, req_rxid, uds_frame)
        elif service == 0x22:
            if req_rxid is None:
                print("[ERROR] ReadDataByIdentifier must be sent to a physical ECU.")
                continue
            UDS_READ_DATA_BY_IDENTIFIER(req_txid, req_rxid, uds_frame)
        elif service == 0x2E:
            if req_rxid is None:
                print("[ERROR] WriteDataByIdentifier must be sent to a physical ECU.")
                continue
            UDS_WRITE_DATA_BY_IDENTIFIER(req_txid, req_rxid, uds_frame)
        elif service == 0x31:
            if req_rxid is None:
                print("[ERROR] RoutineControl must be sent to a physical ECU.")
                continue
            UDS_ROUTINE_CONTROL(req_txid, req_rxid, uds_frame)
        elif service == 0x3E:
            if req_rxid is None:
                print("[ERROR] TesterPresent must be sent to a physical ECU.")
                continue
            # direct TP from prompt (hotkey does the same thing)
            frame = bytes(uds_frame)
            ISOTP_SEND(frame, txid=req_txid, rxid=req_rxid)
            resp = ISOTP_RECEIVE(txid=req_txid, rxid=req_rxid, timeout=2.0)
            if resp is not None:
                print(f"[TESTER] TP Response: {pretty_hex(resp)}")
            else:
                print("[TESTER] No TP response")

# ---------------- Top-level menu ----------------

while True:
    print("\n=== Tester Menu ===")
    print("1) OBD")
    print("2) UDS")
    choice = input("Select option: ").strip()
    if choice  == "1":
        OBD()
    elif choice == "2":
        UDS()
