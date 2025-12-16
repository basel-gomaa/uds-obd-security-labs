# body_ecu_isotp.py  (no size byte, ISO-TP handles length)
import can
import isotp
import time
from isotp import CanMessage
from typing import Dict, Tuple, Optional
from collections import deque
import os
import zlib
from s3_timer import S3Timer
import hmac
import hashlib
import random  # at the top with other imports

SEED_MIN = 0x00001000
SEED_MAX = 0x00001FFF

# ---------------- Security Access config ----------------
MAX_ERROR_COUNT = 3             # how many wrong keys before lockout
LOCKOUT_SECONDS = 30            # lockout duration in seconds
PROTECTED_MODE  = True          # True → protections ON, False → simple XOR mode
MITM_PROTECTION = True          # True → session-token defense ON, False → legacy ECU (no token)

# Fixed 4-byte session token (AABBCCDD)
SESSION_TOKEN_STATIC = b"\xAA\xBB\xCC\xDD"

lockout_until = 0.0             # timestamp until which 0x27 is locked

# ---------------- OBD-II IDs ----------------
functional_address = 0x7DF
body_ecu_physical  = 0x7E0
body_ecu           = 0x7E8  # response id

# ---------------- UDS Session IDs ----------------
DEFAULT_SESSION     = 0x100
PROGRAMMING_SESSION = 0x200
EXTENDED_SESSION    = 0x300


def Hex_to_Int(x) -> int:
    if isinstance(x, int):
        return x
    s = str(x).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)

OBD_PIDS = {  # only used for Mode 09 here
    0x02: "Fuel System Status",
    0x0C: "Engine RPM",
    0x0D: "Vehicle Speed",
    0x05: "Engine Coolant Temperature",
    0x0F: "Intake Air Temperature",
    0x11: "Throttle Position",
    0x1F: "Run Time Since Engine Start",
    0x2F: "Fuel Level Input",
}
VALID_PIDS = set(OBD_PIDS.keys())

def PID_Check(pid_hex) -> int:
    pid = Hex_to_Int(pid_hex)
    return 1 if pid in VALID_PIDS else 0

# ---------------- Bus ----------------
bus = can.Bus(channel='vcan0', interface='socketcan')

def txfn(iso_msg: isotp.CanMessage) -> None:
    msg = can.Message(
        arbitration_id=iso_msg.arbitration_id,
        data=iso_msg.data,
        dlc=iso_msg.dlc,
        is_extended_id=False
    )
    bus.send(msg)

# rx queues per rxid (functional, physical)
_rx_queues: Dict[int, deque] = {
    functional_address: deque(),
    body_ecu_physical: deque(),
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

def vin_to_bytes(vin: str) -> list[int]:
    return [ord(c) for c in vin]
def rpm_to_bytes(rpm: int) -> list[int]:
    raw = rpm * 4
    A = (raw >> 8) & 0xFF
    B = raw & 0xFF
    return [A, B]
def speed_to_bytes(speed: int) -> list[int]:
    return [speed & 0xFF]
VIN = "WP0ZX41S100893123"
rpm_data   = 6904
speed_data = 120
print("ECU: waiting for requests...")

# ---------------- Program file persistence ----------------
PROGRAM_FILE_PATH = "ecu_program.bin"

# Create default file if it doesn't exist
if not os.path.exists(PROGRAM_FILE_PATH):
    with open(PROGRAM_FILE_PATH, "wb") as f:
        # default program image
        f.write(b"\x10\x20\x30\x40")

# Always load current program content
with open(PROGRAM_FILE_PATH, "rb") as f:
    ECU_PROGRAM_FILE = f.read()

def OBD_REQUEST_VEHICLE_INFO(rxid_used, req, body_ecu_id, VIN, PID_Check, vin_to_bytes_fn, isotp_send_fn):
    pid = req[1]

    # PID = 0x02 (VIN)
    if pid == 0x02:
        print(f"[Body ECU] received request: 0x{rxid_used:03X} , "
              f"{' '.join(f'{b:02X}' for b in req)}")
        resp = bytes(vin_to_bytes_fn(VIN))
    else:
        # unsupported PID → NRC
        if not PID_Check(pid):
            resp = bytes([0x7F, req[0]])
        else:
            resp = bytes([0x7F, req[0]])

    print(f"[Body ECU] sending response: 0x{body_ecu_id:03X} , "
          f"{' '.join(f'{b:02X}' for b in resp)}")

    isotp_send_fn(resp, txid=body_ecu_id, rxid=rxid_used)
    time.sleep(0.05)
    return True

def OBD_REQUEST_LIVE_DATA(rxid_used,req,engine_ecu,PID_Check,rpm_to_bytes,speed_to_bytes,rpm_data,speed_data,ISOTP_SEND):

    pid_list = list(req[1:])

    print(f"[Engine ECU] received request: 0x{rxid_used:03X} , "
          f"{' '.join(f'{b:02X}' for b in req)}")

    for pid in pid_list:

        # invalid PID → NRC
        if PID_Check(pid) != 1:
            resp = bytes([0x7F, req[0]])
            print(f"[Engine ECU] NRC for PID {pid:02X}: 0x{engine_ecu:03X} , "
                  f"{' '.join(f'{b:02X}' for b in resp)}")
            ISOTP_SEND(resp, txid=engine_ecu, rxid=rxid_used)
            time.sleep(0.05)
            continue

        resp_mode = 0x41  # 0x01 + 0x40

        if pid == 0x0C:
            user_data = rpm_to_bytes(rpm_data)
        elif pid == 0x0D:
            user_data = speed_to_bytes(speed_data)
        else:
            resp = bytes([0x7F, req[0]])
            print(f"[Engine ECU] NRC for PID {pid:02X}: 0x{engine_ecu:03X} , "
                  f"{' '.join(f'{b:02X}' for b in resp)}")
            ISOTP_SEND(resp, txid=engine_ecu, rxid=rxid_used)
            time.sleep(0.05)
            continue

        resp = bytes([resp_mode, pid] + user_data)
        print(f"[Engine ECU] response for PID {pid:02X}: 0x{engine_ecu:03X} , "
              f"{' '.join(f'{b:02X}' for b in resp)}")
        ISOTP_SEND(resp, txid=engine_ecu, rxid=rxid_used)
        time.sleep(0.05)

    time.sleep(0.05)
    return True

constant = b"\x11\x22\x77\x66"
SECRET_KEY = b"\x93\x11\xfa...\x8b"

def seed_to_key(seed: bytes) -> bytes:
    global constant, PROTECTED_MODE

    if not PROTECTED_MODE:
        constant_int = int.from_bytes(constant, "big")
        seed_int = int.from_bytes(seed, "big")
        key_int = seed_int ^ constant_int
        return key_int.to_bytes(len(seed), "big")

    # PROTECTED_MODE: HMAC-SHA256 over seed, truncated to seed length
    digest = hmac.new(SECRET_KEY, seed, hashlib.sha256).digest()
    return digest[:len(seed)]

# pre-create both stacks
st_func = get_stack(body_ecu, functional_address)
st_phys = get_stack(body_ecu, body_ecu_physical)
stacks = [st_func, st_phys]

# ---------------- S3 timer + globals ----------------
access_flag    = 0      # 1 = security granted
error_num      = 0      # failed key attempts
session        = DEFAULT_SESSION
s3_running     = False
last_seed      = None   # store last seed as bytes

# 32-bit session token used only if MITM_PROTECTION is True
session_token: Optional[bytes] = None

def send_tester_present_cb():
    # ECU normally does not send TesterPresent itself; keep this as a debug hook.
    print("[S3Timer] TesterPresent callback (no frame sent from ECU)")

def s3_expired_callback():
    global session, s3_running, routine_results
    session = DEFAULT_SESSION
    s3_running = False
    # when S3 expires, clear any routine results as well (optional)
    routine_results.clear()
    print(f"session is {session}")
    print("[S3Timer] S3 expired → session returned to Default")

# create global S3Timer instance
s3 = S3Timer(
    send_tester_present_cb=send_tester_present_cb,
    expiry_callback=s3_expired_callback,
    s3_timeout=5,
    auto_tp=False,   # no automatic TesterPresent from ECU
    tp_lead=1.0,
)

def UDS_SECURITY_ACCESS(rxid_used: int, req: list[int]) -> None:

    global access_flag, error_num, last_seed, constant
    global PROTECTED_MODE, lockout_until, MITM_PROTECTION, session_token

    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,"
          f"{' '.join(f'{b:02X}' for b in req)}")

    # Basic length check: must at least have SID + sub-function
    if len(req) < 2:
        sid   = 0x27
        frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
              f"{' '.join(f'{b:02X}' for b in frame)}")
        print("SecurityAccess: Incorrect Message Length")
        return

    sid = req[0]
    sub = req[1]

    # ------------- lockout check (only in PROTECTED_MODE) -------------
    now = time.time()
    if PROTECTED_MODE and lockout_until > now:
        frame = build_nrc(sid, 0x33)  # SecurityAccessDenied
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] LOCKOUT ACTIVE until {lockout_until:.2f}, deny 0x27")
        return

    # --------------- 27 01: requestSeed ---------------
    if sub == 0x01:
        # generate new seed in [SEED_MIN .. SEED_MAX] and reset state
        seed_int = random.randint(SEED_MIN, SEED_MAX)
        last_seed = seed_int.to_bytes(len(constant), byteorder="big")

        # clear any old session-token on new challenge
        session_token = None

        response = bytes([sid + 0x40, sub]) + last_seed
        ISOTP_SEND(response, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
              f"{' '.join(f'{b:02X}' for b in response)}")
        print(f"SecurityAccess: Seed generated {last_seed.hex()}")
        return

    # --------------- 27 02: sendKey ---------------
    if sub == 0x02:
        if last_seed is None:
            # No previous seed → conditions not correct
            frame = build_nrc(sid, NRC_CONDITIONS_NOT_CORRECT)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
                  f"{' '.join(f'{b:02X}' for b in frame)}")
            print("SecurityAccess: No seed stored, conditions not correct")
            return

        # Key must follow SID+sub
        if len(req) < 2 + len(last_seed):
            frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
                  f"{' '.join(f'{b:02X}' for b in frame)}")
            print("SecurityAccess: Key length incorrect")
            return

        received_key = bytes(req[2:])
        expected_key = seed_to_key(last_seed)

        print(f"[Body ECU] SecurityAccess: received key {received_key.hex()}, "
              f"expected {expected_key.hex()}")

        if received_key == expected_key:
            access_flag = 1
            error_num   = 0

            if PROTECTED_MODE:
                # one-time seed to reduce replay
                last_seed = None

            if MITM_PROTECTION:
                # -------- Defense #3: Session token --------
                # Use fixed 4-byte token AABBCCDD instead of random
                session_token = SESSION_TOKEN_STATIC

                # Response: 67 02 AA BB CC DD
                frame = bytes([sid + 0x40, sub]) + session_token
                print(f"SecurityAccess: ACCESS GRANTED, session token={session_token.hex()}")
            else:
                # Legacy behavior (no MITM protection):
                # Response: 67 02 <key>
                session_token = None
                frame = bytes([sid + 0x40, sub]) + expected_key
                print("SecurityAccess: ACCESS GRANTED (no MITM protection)")

            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
                  f"{' '.join(f'{b:02X}' for b in frame)}")
            return

        # wrong key
        access_flag = 0

        if not PROTECTED_MODE:
            # In insecure XOR mode: unlimited wrong attempts, always 0x35
            frame = build_nrc(sid, 0x35)  # InvalidKey
            print("SecurityAccess: Invalid Key (no limit in unprotected mode)")
        else:
            # Protected mode: 3-try limit + lockout
            if error_num < MAX_ERROR_COUNT - 1:
                frame = build_nrc(sid, 0x35)  # InvalidKey
                error_num += 1
                print("SecurityAccess: Invalid Key")
            else:
                # reached max errors
                error_num = 0
                frame = build_nrc(sid, 0x33)  # SecurityAccessDenied
                print("SecurityAccess: ACCESS FAILED FOR THREE TIMES")

                # start lockout window only in protected mode
                lockout_until = time.time() + LOCKOUT_SECONDS
                print(f"SecurityAccess: LOCKOUT for {LOCKOUT_SECONDS} seconds")

        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
              f"{' '.join(f'{b:02X}' for b in frame)}")
        return

    # --------------- unsupported sub-function ---------------
    frame = build_nrc(sid, NRC_SUBFUNC_NOT_SUPPORTED)
    ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
    print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,"
          f"{' '.join(f'{b:02X}' for b in frame)}")
    print(f"SecurityAccess: SubFunction 0x{sub:02X} Not Supported")

def UDS_DIAGNOSTIC_SESSION_CONTROL(rxid_used: int, req: list[int]) -> None:
    global session, s3_running, session_token, MITM_PROTECTION, access_flag
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    sid = req[0]

    # Default Session
    if req[1] == 0x01:
        session = DEFAULT_SESSION
        s3.stop()
        s3_running = False
        frame = bytes([0x50, req[1]])
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Default Session is on")
        return

    # Programming Session (0x10 02)
    if req[1] == 0x02:
        # -------- Legacy behavior (no MITM protection) --------
        if not MITM_PROTECTION:
            if access_flag == 1:
                session = PROGRAMMING_SESSION
                frame = bytes([0x50, req[1]])
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Programming Session is on")
                s3.start()
                s3_running = True
                print("[S3Timer] Started after successful Diagnostic Session")
            else:
                frame = bytes([0x7F, sid, 0x33])
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Security Access Denied (legacy DSC)")
            return

        # -------- MITM-protected behavior: require session token --------
        # Expect: 10 02 <4-byte token>  → total len = 6
        if len(req) != 6:
            frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Programming: Incorrect Message Length (token missing)")
            return

        if access_flag != 1 or session_token is None:
            frame = bytes([0x7F, sid, 0x33])  # SecurityAccessDenied
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Programming: Security Access Denied (no token)")
            return

        token_rx = bytes(req[2:6])
        if token_rx != session_token:
            frame = bytes([0x7F, sid, 0x33])
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Programming: Invalid session token")
            return

        # Token valid → switch session; keep token so it can be reused after S3 expiry
        session = PROGRAMMING_SESSION
        frame = bytes([0x50, req[1]])
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Programming Session is on (token verified)")
        s3.start()
        s3_running = True
        print("[S3Timer] Started after successful Diagnostic Session")
        return

    # Extended Session (0x10 03)
    if req[1] == 0x03:
        # -------- Legacy behavior (no MITM protection) --------
        if not MITM_PROTECTION:
            if access_flag == 1:
                session = EXTENDED_SESSION
                frame = bytes([0x50, req[1]])
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Extended Session is on")
                s3.start()
                s3_running = True
                print("[S3Timer] Started after successful Diagnostic Session")
            else:
                frame = bytes([0x7F, sid, 0x33])
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Security Access Denied (legacy DSC)")
            return

        # -------- MITM-protected behavior: require session token --------
        # Expect: 10 03 <4-byte token> → total len = 6
        if len(req) != 6:
            frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Extended: Incorrect Message Length (token missing)")
            return

        if access_flag != 1 or session_token is None:
            frame = bytes([0x7F, sid, 0x33])
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Extended: Security Access Denied (no token)")
            return

        token_rx = bytes(req[2:6])
        if token_rx != session_token:
            frame = bytes([0x7F, sid, 0x33])
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("DSC Extended: Invalid session token")
            return

        session = EXTENDED_SESSION
        frame = bytes([0x50, req[1]])
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Extended Session is on (token verified)")
        s3.start()
        s3_running = True
        print("[S3Timer] Started after successful Diagnostic Session")
        return


def UDS_ECU_RESET(rxid_used: int, req: list[int]) -> None:
    global session, access_flag, error_num, s3_running, routine_results, session_token
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    sid = req[0]

    # BLOCK RESET IF SECURITY NOT GRANTED
    if access_flag != 1:
        frame = build_nrc(sid, 0x33)  # SecurityAccessDenied → 7F 11 33
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("ECU Reset blocked (Security Access Denied)")
        return

    # LENGTH CHECK
    if len(req) < 2:
        frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("ECU Reset: Incorrect Message Length")
        return

    sub = req[1]

    # VALID SUB-FUNCTIONS 0x01 (hard reset) and 0x03 (soft reset)
    if sub in (0x01, 0x03):
        access_flag   = 0
        error_num     = 0
        session       = DEFAULT_SESSION
        session_token = None

        # Stop S3 and clear routine results
        s3.stop()
        s3_running = False
        routine_results.clear()

        print(f"session is {session}")

        frame = bytes([sid + 0x40, sub])  # 51 01 or 51 03
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("ECU Reset is Done.")
        return

    # UNSUPPORTED SUB-FUNCTION
    frame = build_nrc(sid, NRC_SUBFUNC_NOT_SUPPORTED)
    ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
    print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
    print("ECU Reset: SubFunction Not Supported")

# ---------------- UDS negative response codes ----------------
NRC_INCORRECT_LENGTH       = 0x13
NRC_REQUEST_OUT_OF_RANGE   = 0x31
NRC_REQUEST_NOT_ALLOWED    = 0x7E
NRC_SUBFUNC_NOT_SUPPORTED  = 0x12
NRC_CONDITIONS_NOT_CORRECT = 0x22

def build_nrc(sid: int, code: int) -> bytes:
    # 0x7F, SID, NRC
    return bytes([0x7F, sid, code])

def build_pos_read(did: int, data: bytes) -> bytes:
    # 0x62 DID_H DID_L <data...>
    pos_sid = 0x22 + 0x40
    return bytes([pos_sid, (did >> 8) & 0xFF, did & 0xFF]) + data

def build_pos_write(did: int) -> bytes:
    # 0x6E DID_H DID_L
    pos_sid = 0x2E + 0x40
    return bytes([pos_sid, (did >> 8) & 0xFF, did & 0xFF])

# ---------------- RoutineControl helpers ----------------
SID_ROUTINE = 0x31

def build_pos_routine_start(rid: int, status: int = 0x00) -> bytes:
    # 0x71 0x01 RID_H RID_L STATUS
    return bytes([SID_ROUTINE + 0x40, 0x01, (rid >> 8) & 0xFF, rid & 0xFF, status])

def build_pos_routine_result(rid: int, data_bytes: bytes, status: int = 0x00) -> bytes:
    # 0x71 0x03 RID_H RID_L <data...> STATUS
    return bytes([SID_ROUTINE + 0x40, 0x03, (rid >> 8) & 0xFF, rid & 0xFF]) + data_bytes + bytes([status])

# ---------------- DIDs and ECU data ----------------
DID_VIN    = 0xF190
DID_SERIAL = 0xF18C
DID_PROG   = 0xF1A0

# Serial example (VIN already defined as string)
ECU_SERIAL = b"SN1234567890"

def check_session_permission_for_read(did: int) -> bool:
    """
    Read permissions:
      - VIN + SERIAL: only in Programming or Extended
      - PROG: allowed in all sessions
    """
    if did in (DID_VIN, DID_SERIAL):
        return session in (PROGRAMMING_SESSION, EXTENDED_SESSION)
    if did == DID_PROG:
        return session in (DEFAULT_SESSION, PROGRAMMING_SESSION, EXTENDED_SESSION)
    return False

def check_session_permission_for_write(did: int) -> bool:
    """
    Write permissions:
      - PROG: only in Programming or Extended
    """
    if did == DID_PROG:
        return session in (PROGRAMMING_SESSION, EXTENDED_SESSION)
    return False

def UDS_READ_DATA_BY_IDENTIFIER(rxid_used: int, req: list[int]) -> None:
    """
    Service 0x22: ReadDataByIdentifier
    req = [0x22, DID_H, DID_L]
    Sends response via ISOTP_SEND, does not return it.
    """
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    # Must be exactly SID + DID_H + DID_L
    if len(req) != 3:
        frame = build_nrc(0x22, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Incorrect Message Length")
        return

    did = (req[1] << 8) | req[2]

    # Supported DIDs
    if did not in (DID_VIN, DID_SERIAL, DID_PROG):
        frame = build_nrc(0x22, NRC_REQUEST_OUT_OF_RANGE)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Request Out Of Range (unsupported DID)")
        return

    # Session permission
    if not check_session_permission_for_read(did):
        frame = build_nrc(0x22, NRC_CONDITIONS_NOT_CORRECT)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Conditions Not Correct")
        return

    # Select data
    if did == DID_VIN:
        data = bytes(vin_to_bytes(VIN))
    elif did == DID_SERIAL:
        data = ECU_SERIAL
    elif did == DID_PROG:
        data = ECU_PROGRAM_FILE
    else:
        frame = build_nrc(0x22, NRC_REQUEST_OUT_OF_RANGE)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Request Out Of Range (logic fallthrough)")
        return

    # Positive response
    frame = build_pos_read(did, data)
    ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
    print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")

def UDS_WRITE_DATA_BY_IDENTIFIER(rxid_used: int, req: list[int]) -> None:
    """
    Service 0x2E: WriteDataByIdentifier
    req = [0x2E, DID_H, DID_L, <data...>]
    Sends response via ISOTP_SEND, does not return it.
    """
    global ECU_PROGRAM_FILE, access_flag
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    did = (req[1] << 8) | req[2]
    data = bytes(req[3:])

    if access_flag != 1:
        frame = build_nrc(0x2E, 0x33)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Request Not Allowed (Security Access Denied)")
        return

    if len(req) < 4:
        frame = build_nrc(0x2E, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Incorrect Message Length")
        return

    # Session permission
    if not check_session_permission_for_write(did):
        frame = build_nrc(0x2E, NRC_REQUEST_NOT_ALLOWED)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Request Not Allowed In This Session (write)")
        return


    # Perform write and persist
    ECU_PROGRAM_FILE = data
    try:
        with open(PROGRAM_FILE_PATH, "wb") as f:
            f.write(ECU_PROGRAM_FILE)
    except Exception as e:
        print(f"[Body ECU] Failed to persist program file: {e}")
        frame = build_nrc(0x2E, NRC_REQUEST_OUT_OF_RANGE)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("Generic failure during write")
        return

    # Positive response
    frame = build_pos_write(did)
    ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
    print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")

# ---------------- RoutineControl: 0x1234 and 0x5678 ----------------
FIXED_RPM   = 3000
FIXED_SPEED = 80
RPM_RANGE   = (0, 8000)
SPEED_RANGE = (0, 250)

# Routine states
routine_results = {}

# Example checksum data: VIN bytes + current program file
CHECKSUM_DATA = bytes(vin_to_bytes(VIN)) + ECU_PROGRAM_FILE

def UDS_ROUTINE_CONTROL(rxid_used: int, req: list[int]) -> None:
    """
    Service 0x31: RoutineControl
    req = [0x31, subfunc, RID_H, RID_L, ...optional data...]
    Supports:
      - RID 0x1234: Self-test (RPM/SPEED)
      - RID 0x5678 (coded as 0x1456 here): CRC32 checksum over CHECKSUM_DATA
        (both subfunctions only allowed in Programming/Extended sessions)
    Sends response via ISOTP_SEND, does not return it.
    """
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    if len(req) < 4:
        frame = build_nrc(0x31, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("RoutineControl: Incorrect Message Length")
        return

    subfunc = req[1]
    rid = (req[2] << 8) | req[3]

    # ------------------- Routine 0x1234: Self-Test -------------------
    if rid == 0x1234:
        if subfunc == 0x01:  # Start routine
            rpm_ok   = RPM_RANGE[0]   <= FIXED_RPM   <= RPM_RANGE[1]
            speed_ok = SPEED_RANGE[0] <= FIXED_SPEED <= SPEED_RANGE[1]
            status = 0x00 if (rpm_ok and speed_ok) else 0x01

            routine_results[rid] = {
                "RPM": FIXED_RPM,
                "Speed": FIXED_SPEED,
                "STATUS": status
            }

            print(f"[Body ECU] Routine 0x1234 Start: RPM={FIXED_RPM}, Speed={FIXED_SPEED}, Status={status}")
            frame = build_pos_routine_start(rid, status)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            return

        elif subfunc == 0x03:  # Request results
            if rid not in routine_results:
                frame = build_nrc(0x31, NRC_CONDITIONS_NOT_CORRECT)
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Routine 0x1234: Conditions Not Correct (no previous start)")
                return

            res = routine_results[rid]
            rpm_h = (res["RPM"] >> 8) & 0xFF
            rpm_l = res["RPM"] & 0xFF
            speed = res["Speed"] & 0xFF
            status = res["STATUS"]
            data_bytes = bytes([rpm_h, rpm_l, speed])
            frame = build_pos_routine_result(rid, data_bytes, status)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            return

        else:
            frame = build_nrc(0x31, NRC_SUBFUNC_NOT_SUPPORTED)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("Routine 0x1234: SubFunction Not Supported")
            return

    # ------------------- Routine 0x5678: CRC32 checksum (rid == 0x1456) -------------------
    elif rid == 0x1456:
        # Both subfunctions (0x01 start, 0x03 results) allowed only in
        # Programming or Extended sessions.
        if session not in (PROGRAMMING_SESSION, EXTENDED_SESSION):
            frame = build_nrc(0x31, NRC_REQUEST_NOT_ALLOWED)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("Routine 0x5678: Request Not Allowed In This Session (both subfunctions)")
            return

        if subfunc == 0x01:  # Start checksum
            crc32_val = zlib.crc32(CHECKSUM_DATA) & 0xFFFFFFFF
            routine_results[rid] = {
                "CRC32": crc32_val,
                "STATUS": 0x00
            }
            print(f"[Body ECU] Routine 0x5678 Start: CRC32={crc32_val:08X}")
            frame = build_pos_routine_start(rid, 0x00)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            return

        elif subfunc == 0x03:  # Request results
            if rid not in routine_results:
                frame = build_nrc(0x31, NRC_CONDITIONS_NOT_CORRECT)
                ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
                print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
                print("Routine 0x5678: Conditions Not Correct (no previous start)")
                return

            val = routine_results[rid]["CRC32"]
            status = routine_results[rid]["STATUS"]
            data_bytes = val.to_bytes(4, "big")
            frame = build_pos_routine_result(rid, data_bytes, status)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            return

        else:
            frame = build_nrc(0x31, NRC_SUBFUNC_NOT_SUPPORTED)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print("Routine 0x5678: SubFunction Not Supported")
            return

    # ------------------- Unknown Routine ID -------------------
    else:
        frame = build_nrc(0x31, NRC_REQUEST_OUT_OF_RANGE)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print(f"RoutineControl: RID 0x{rid:04X} Request Out Of Range")
        return

# ---------------- TesterPresent (0x3E) ----------------

def UDS_TESTER_PRESENT(rxid_used: int, req: list[int]) -> None:
    global s3_running
    print(f"[Body ECU] received request: 0x{rxid_used:03X} ,{' '.join(f'{b:02X}' for b in req)}")

    sid = req[0]

    # Must be 3E 00
    if len(req) != 2:
        frame = build_nrc(sid, NRC_INCORRECT_LENGTH)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("TesterPresent: Incorrect Message Length")
        return

    # Allow TP only while S3 is running AND session is Programming/Extended
    if (not s3_running) or (session not in (PROGRAMMING_SESSION, EXTENDED_SESSION)):
        frame = build_nrc(sid, NRC_REQUEST_NOT_ALLOWED)
        ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
        print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
        print("TesterPresent: Request Not Allowed (S3 not running or wrong session)")
        return

    # Reset S3 and acknowledge
    s3.reset()
    frame = bytes([sid + 0x40, req[1]])  # 7E 00
    ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
    print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
    print("TesterPresent: S3 timer reset")

# ---------------- Main loop ----------------
while True:
    req, rxid_used = ISOTP_MULTI_RECEIVE(stacks, timeout=5.0)
    if req is None:
        continue

    # no-size: UDS vs OBD mode 09 & 01
    if (req[0] != 0x09 and req[0] != 0x01):
        if req[0] == 0x27:
            UDS_SECURITY_ACCESS(rxid_used, req)
        elif req[0] == 0x10:
            UDS_DIAGNOSTIC_SESSION_CONTROL(rxid_used, req)
        elif req[0] == 0x11:
            UDS_ECU_RESET(rxid_used, req)
        elif req[0] == 0x22:
            UDS_READ_DATA_BY_IDENTIFIER(rxid_used, req)
        elif req[0] == 0x2E:
            UDS_WRITE_DATA_BY_IDENTIFIER(rxid_used, req)
        elif req[0] == 0x31:
            UDS_ROUTINE_CONTROL(rxid_used, req)
        elif req[0] == 0x3E:
            UDS_TESTER_PRESENT(rxid_used, req)
        else:
            # Unsupported SID → ServiceNotSupported (0x11)
            sid = req[0]
            frame = build_nrc(sid, 0x11)
            ISOTP_SEND(frame, txid=body_ecu, rxid=rxid_used)
            print(f"[Body ECU] sending response: 0x{body_ecu:03X} ,{' '.join(f'{b:02X}' for b in frame)}")
            print(f"Service 0x{sid:02X}: Service Not Supported")
    elif req[0] == 0x09:
        OBD_REQUEST_VEHICLE_INFO(rxid_used, req, body_ecu, VIN, PID_Check, vin_to_bytes, ISOTP_SEND)
    elif req[0] == 0x01:
        OBD_REQUEST_LIVE_DATA(rxid_used, req, body_ecu, PID_Check, rpm_to_bytes, speed_to_bytes, rpm_data, speed_data, ISOTP_SEND)
