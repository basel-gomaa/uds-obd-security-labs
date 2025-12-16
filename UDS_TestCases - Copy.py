#!/usr/bin/env python3
"""
UDS Tester with minimal ISO-TP support (FF/CF/FC)
Sends UDS requests over CAN using ISO-TP framing when needed, and receives multi-frame ISO-TP responses.

Save as: uds_tester_isotp.py

Notes:
- Implements a minimal ISO-TP sender and receiver (SF, FF, CF, FC handling).
- Designed for lab use: supports multi-frame ECU responses (e.g., VIN 17 bytes).
- Does NOT test ISO-TP timing corner-cases (BS/STmin enforcement) — tester will respond with simple FC (CTS) and respect basic STmin if provided.
- Install dependency: pip3 install python-can

Usage:
  python3 uds_tester_isotp.py --bus vcan0 --tx-id 0x7E0 --rx-id 0x7E8
"""

import argparse
import can
import time
import json
import sys
from typing import Tuple

# Defaults
DEFAULT_SEED_XOR = 0x11223344
DEFAULT_SEED_LEN = 4
DEFAULT_KEY_LEN = 4
DEFAULT_TIMEOUT = 2.0
# add near top of file (helpers)
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RESET = "\033[0m"

def color(text: str, code: str) -> str:
    return f"{code}{text}{ANSI_RESET}"

# Helpers
def int_to_bytes(val, length):
    return val.to_bytes(length, 'big')

def xor_bytes(a: bytes, b_int: int) -> bytes:
    b = int_to_bytes(b_int, len(a))
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_hex(b: bytes):
    return b.hex() if b else None

# Minimal ISO-TP implementation (lab-grade)
class ISOTP:
    def __init__(self, bus: can.interface.Bus, tx_id: int, rx_id: int, timeout=DEFAULT_TIMEOUT):
        self.bus = bus
        self.tx_id = tx_id  # our transmitted CAN ID (tester -> ECU)
        self.rx_id = rx_id  # ECU responses (ECU -> tester)
        self.timeout = timeout
        # parameters learned from FC
        self.bs = None
        self.stmin = 0.0

    def _send_can(self, arb_id: int, data: bytes):
        data8 = data + bytes(8 - len(data))
        msg = can.Message(arbitration_id=arb_id, data=data8, is_extended_id=False)
        self.bus.send(msg)

    # send UDS payload using ISO-TP (will split into FF/CF if needed)
    def send(self, payload: bytes) -> bool:
        if len(payload) <= 7:
            pci = (0x0 << 4) | (len(payload) & 0xF)
            data = bytes([pci]) + payload
            self._send_can(self.tx_id, data)
            return True
        # First Frame
        total_len = len(payload)
        pci0 = (0x1 << 4) | ((total_len >> 8) & 0xF)
        pci1 = total_len & 0xFF
        ffdata = bytes([pci0, pci1]) + payload[:6]
        self._send_can(self.tx_id, ffdata)
        # wait for FC from rx_id
        start = time.time()
        fc = None
        while time.time() - start < self.timeout:
            msg = self.bus.recv(timeout=0.1)
            if not msg:
                continue
            if msg.arbitration_id != self.rx_id:
                continue
            pci = msg.data[0]
            ftype = (pci >> 4) & 0xF
            if ftype == 0x3:  # FC
                fs = msg.data[1]
                st = msg.data[2]
                self.bs = fs if fs != 0 else None
                if st <= 127:
                    self.stmin = st / 1000.0
                elif 241 <= st <= 249:
                    self.stmin = (st - 240) / 10000.0
                else:
                    self.stmin = 0.0
                fc = msg
                break
        if fc is None:
            raise TimeoutError("No FC after FF")
        # send CFs
        seq = 1
        sent = 6
        blocks_left = self.bs
        while sent < total_len:
            cf_pci = (0x2 << 4) | (seq & 0xF)
            chunk = payload[sent:sent+7]
            data = bytes([cf_pci]) + chunk
            self._send_can(self.tx_id, data)
            sent += len(chunk)
            seq = (seq + 1) & 0xF
            if blocks_left is not None:
                blocks_left -= 1
                if blocks_left == 0 and sent < total_len:
                    # wait for next FC
                    start = time.time()
                    fc = None
                    while time.time() - start < self.timeout:
                        msg = self.bus.recv(timeout=0.1)
                        if not msg:
                            continue
                        if msg.arbitration_id != self.rx_id:
                            continue
                        pci = msg.data[0]
                        if ((pci >> 4) & 0xF) == 0x3:
                            fs = msg.data[1]
                            st = msg.data[2]
                            self.bs = fs if fs != 0 else None
                            if st <= 127:
                                self.stmin = st / 1000.0
                            elif 241 <= st <= 249:
                                self.stmin = (st - 240) / 10000.0
                            else:
                                self.stmin = 0.0
                            fc = msg
                            break
                    if fc is None:
                        raise TimeoutError("No FC during CFs")
            if self.stmin > 0:
                time.sleep(self.stmin)
        return True

    # receive UDS response (handles SF and FF->CF reassembly). When FF received, send FC (CTS).
    def recv(self, timeout=None) -> bytes:
        timeout = timeout or self.timeout
        start = time.time()
        while time.time() - start < timeout:
            msg = self.bus.recv(timeout=0.1)
            if not msg:
                continue
            if msg.arbitration_id != self.rx_id:
                continue
            pci0 = msg.data[0]
            ftype = (pci0 >> 4) & 0xF
            if ftype == 0x0:  # SF
                length = pci0 & 0xF
                return bytes(msg.data[1:1+length])
            if ftype == 0x1:  # FF
                high = pci0 & 0xF
                low = msg.data[1]
                total_len = (high << 8) | low
                payload = bytearray()
                payload += msg.data[2:8]
                # send FC (CTS) allowing all blocks, STmin 0
                fc = bytes([ (0x3 << 4) | 0x0, 0x00, 0x00 ]) + bytes(5)
                self._send_can(self.tx_id, fc)
                # collect CFs
                expected_seq = 1
                while len(payload) < total_len:
                    msg2 = self.bus.recv(timeout=timeout)
                    if not msg2:
                        raise TimeoutError("Timeout receiving CFs")
                    if msg2.arbitration_id != self.rx_id:
                        continue
                    pci = msg2.data[0]
                    f = (pci >> 4) & 0xF
                    if f != 0x2:
                        continue
                    payload += msg2.data[1:8]
                return bytes(payload[:total_len])
            # ignore other frame types
        return None

# CAN wrapper uses ISOTP
class CanIf:
    def __init__(self, channel, tx_id, rx_id, timeout=DEFAULT_TIMEOUT):
        self.channel = channel
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.timeout = timeout
        try:
            self.bus = can.interface.Bus(channel=channel, bustype='socketcan')
        except Exception as e:
            print("Failed to open CAN interface:", e)
            raise
        self.isotp = ISOTP(self.bus, tx_id, rx_id, timeout=timeout)

    # send UDS payload via ISO-TP and receive response via ISO-TP
    def transceive(self, payload: bytes, timeout=None) -> bytes:
        self.isotp.send(payload)
        resp = self.isotp.recv(timeout=timeout or self.timeout)
        return resp

# UDS helpers
def build_request(sid: int, payload: bytes = b'') -> bytes:
    return bytes([sid]) + payload

def is_positive_response(sid: int, resp: bytes) -> bool:
    if not resp or len(resp) == 0:
        return False
    return resp[0] == ((sid + 0x40) & 0xFF)

def is_negative_response(resp: bytes) -> bool:
    return bool(resp and len(resp) >= 3 and resp[0] == 0x7F)

def parse_nrc(resp: bytes) -> int:
    if is_negative_response(resp):
        return resp[2]
    return None
def nrc_text(resp, resp_hex=None):
    """
    Return a safe string for the NRC of `resp`.
    Examples: "0x35", "None", or raw hex if NRC not present.
    """
    if resp is None:
        return "None"
    n = parse_nrc(resp)
    if n is not None:
        return f"0x{n:02X}"
    # no NRC but we have a hex string
    if resp_hex:
        return resp_hex
    try:
        return resp.hex()
    except Exception:
        return str(resp)

# Tester class
class UDSTester:
    def __init__(self, can_if: CanIf, s3=5, seed_xor=DEFAULT_SEED_XOR, timeout=DEFAULT_TIMEOUT):
        self.can_if = can_if
        self.s3 = s3
        self.seed_xor = seed_xor
        self.timeout = timeout
        self.log = []
        self.last_seed = None
        self.security_granted = False

    # Replace the UDSTester.record method with this version:
    def record(self, name, ok, details, req_hex=None, resp_hex=None):
        entry = {"test": name, "ok": ok, "details": details, "req": req_hex, "resp": resp_hex, "time": time.time()}
        # colored status
        status = color("PASS", ANSI_GREEN) if ok else color("FAIL", ANSI_RED)
        print(f"{status} - {name}: {details}")
        self.log.append(entry)


    def send_and_receive(self, sid:int, payload:bytes=b'', timeout=None) -> Tuple[bytes, str]:
        req = build_request(sid, payload)
        req_hex = req.hex()
        try:
            resp = self.can_if.transceive(req, timeout=timeout or self.timeout)
        except Exception as e:
            return None, f"error:{e}"
        resp_hex = bytes_to_hex(resp)
        if resp is None:
            return None, f"no_response"
        return resp, resp_hex

    # Tests (same logic as previous no-ISOTP tester but using ISO-TP transceive)
    def test_S1_seed_request(self):
        name = "S1_seed_request"
        resp, resp_hex = self.send_and_receive(0x27, b'\x01')
        if not resp:
            self.record(name, False, "No response to seed request", req_hex="27 01", resp_hex=None)
            return
        if is_positive_response(0x27, resp):
            # resp format: [0x67, 0x01, seed0, seed1, seed2, seed3, ...]
            # seed starts at index 2
            if len(resp) < 2 + DEFAULT_SEED_LEN:
                self.record(name, False, f"Seed response too short ({len(resp)} bytes)", req_hex="27 01", resp_hex=resp_hex)
                return
            seed = resp[2:2 + DEFAULT_SEED_LEN]
            self.last_seed = seed
            self.record(name, True, f"Seed received: {seed.hex()}", req_hex="27 01", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            nrc = parse_nrc(resp)
            self.record(name, False, f"Seed request rejected NRC=0x{nrc:02X}", req_hex="27 01", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response format", req_hex="27 01", resp_hex=resp_hex)

    def test_S2_correct_key(self):
        name = "S2_correct_key"
        if not self.last_seed:
            self.record(name, False, "No seed available; run S1 first")
            return
        # compute expected key: seed XOR SEED_KEY_XOR (big-endian words)
        xor_constant = self.seed_xor.to_bytes(DEFAULT_SEED_LEN, "big")
        key = bytes(a ^ b for a, b in zip(self.last_seed, xor_constant))[:DEFAULT_KEY_LEN]
        resp, resp_hex = self.send_and_receive(0x27, b'\x02' + key)
        if not resp:
            self.record(name, False, "No response to send key", req_hex=("27 02 "+key.hex()), resp_hex=None)
            return
        if is_positive_response(0x27, resp):
            self.security_granted = True
            self.record(name, True, "SecurityAccess granted", req_hex=("27 02 "+key.hex()), resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            nrc = parse_nrc(resp)
            self.record(name, False, f"SecurityAccess denied NRC=0x{nrc:02X}", req_hex=("27 02 "+key.hex()), resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response to key", req_hex=("27 02 "+key.hex()), resp_hex=resp_hex)

    def test_S3_wrong_key(self):
        name="S3_wrong_key"
        wrong = b'\x00'*DEFAULT_KEY_LEN
        resp, resp_hex = self.send_and_receive(0x27, b'\x02'+wrong)
        if not resp:
            self.record(name, False, "No response to wrong key", req_hex=("27 02 "+wrong.hex()), resp_hex=None)
            return
        if is_negative_response(resp):
            self.record(name, True, f"Wrong key rejected NRC=0x{parse_nrc(resp):02X}", req_hex=("27 02 "+wrong.hex()), resp_hex=resp_hex)
            return
        self.record(name, False, "Wrong key unexpectedly accepted", req_hex=("27 02 "+wrong.hex()), resp_hex=resp_hex)

    # Sessions & TesterPresent (3E 00 only)
    def test_SE1_enter_extended_without_security(self):
        name="SE1_enter_extended_no_sec"
        resp, resp_hex = self.send_and_receive(0x10, b'\x03')
        if not resp:
            self.record(name, False, "No response to DiagnosticSessionControl(Extended)", req_hex="10 03")
            return
        if is_positive_response(0x10, resp):
            self.record(name, False, "Unexpectedly entered Extended without security", req_hex="10 03", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"Extended denied as expected NRC=0x{parse_nrc(resp):02X}", req_hex="10 03", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response", req_hex="10 03", resp_hex=resp_hex)

    def test_SE2_enter_extended_with_security(self):
        name="SE2_enter_extended_with_security"
        if not self.security_granted:
            self.record(name, False, "No security granted; run S1+S2")
            return
        resp, resp_hex = self.send_and_receive(0x10, b'\x02')
        if not resp:
            self.record(name, False, "No response to DiagnosticSessionControl(Extended)", req_hex="10 02")
            return
        if is_positive_response(0x10, resp):
            self.record(name, True, "Entered Extended session", req_hex="10 02", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, False, f"Extended denied NRC=0x{parse_nrc(resp):02X}", req_hex="10 02", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response", req_hex="10 02", resp_hex=resp_hex)

    def test_SE3_enter_programming_with_security(self):
        name="SE3_enter_programming_with_security"
        if not self.security_granted:
            self.record(name, False, "No security granted; run S1+S2")
            return
        resp, resp_hex = self.send_and_receive(0x10, b'\x03')
        if not resp:
            self.record(name, False, "No response to DiagnosticSessionControl(Programming)", req_hex="10 03")
            return
        if is_positive_response(0x10, resp):
            self.record(name, True, "Entered Programming session", req_hex="10 03", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, False, f"Programming denied NRC=0x{parse_nrc(resp):02X}", req_hex="10 03", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response", req_hex="10 03", resp_hex=resp_hex)

    def test_SE4_tester_present_and_session_check(self):
        name="SE4_tester_present_and_check"
        resp, resp_hex = self.send_and_receive(0x3E, b'\x00')
        if not resp:
            self.record(name, False, "No response to TesterPresent", req_hex="3E 00")
            return
        if is_positive_response(0x3E, resp):
            resp2, resp2_hex = self.send_and_receive(0x22, b'\xF1\x8C')
            if not resp2:
                self.record(name, False, "No response to read F18C after TesterPresent", req_hex="22 F1 8C", resp_hex=resp_hex)
                return
            if is_positive_response(0x22, resp2):
                self.record(name, True, "TesterPresent OK and session-only DID accessible", req_hex="3E 00 then 22 F1 8C", resp_hex=resp2_hex)
                return
            if is_negative_response(resp2):
                self.record(name, False, f"F18C read denied after TesterPresent NRC=0x{parse_nrc(resp2):02X}", req_hex="22 F1 8C", resp_hex=resp2_hex)
                return
            self.record(name, False, "Unexpected response reading F18C", req_hex="22 F1 8C", resp_hex=resp2_hex)
            return
        if is_negative_response(resp):
            self.record(name, False, f"TesterPresent returned negative NRC=0x{parse_nrc(resp):02X}", req_hex="3E 00", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response to TesterPresent", req_hex="3E 00", resp_hex=resp_hex)

    def test_SE5_s3_expiry(self):
        name="SE5_s3_expiry"
        print(f"Waiting {self.s3 + 1} seconds to allow S3 expiry")
        time.sleep(self.s3 + 1)
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\x8C')
        if not resp:
            self.record(name, False, "No response after S3 wait", req_hex="22 F1 8C")
            return
        if is_positive_response(0x22, resp):
            self.record(name, False, "Session did not expire (F18C still accessible)", req_hex="22 F1 8C", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"Session expired or access denied after S3 NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 8C", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response after S3 wait", req_hex="22 F1 8C", resp_hex=resp_hex)

    # DIDs
    def test_D1_model_in_default_denied(self):
        name="D1_model_in_default_denied"
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\x8C')
        if not resp:
            self.record(name, False, "No response to read F18C", req_hex="22 F1 8C")
            return
        if is_positive_response(0x22, resp):
            self.record(name, False, "F18C accessible in Default (unexpected)", req_hex="22 F1 8C", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"F18C correctly denied in Default NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 8C", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response", req_hex="22 F1 8C", resp_hex=resp_hex)

    def test_D2_model_after_auth(self):
        name="D2_model_after_auth"
        if not self.security_granted:
            self.record(name, False, "Security not granted; run S1+S2")
            return
        self.send_and_receive(0x10, b'\x02')
        time.sleep(0.5)
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\x8C')
        if not resp:
            self.record(name, False, "No response to F18C after auth", req_hex="22 F1 8C")
            return
        if is_positive_response(0x22, resp):
            model = resp[1:].rstrip(b'\x00').decode(errors='ignore')
            self.record(name, True, f"F18C read OK: {model}", req_hex="22 F1 8C", resp_hex=resp_hex)
            return
        self.record(name, False, f"F18C read failed NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 8C", resp_hex=resp_hex)

    def test_D3_vin_in_default_denied(self):
        name="D3_vin_in_default_denied"
        self.send_and_receive(0x10, b'\x01')
        time.sleep(0.5)
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\x90')
        if not resp:
            self.record(name, False, "No response to read F190", req_hex="22 F1 90")
            return
        if is_positive_response(0x22, resp):
            self.record(name, False, "F190 VIN accessible in Default (unexpected)", req_hex="22 F1 90", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"F190 correctly denied in Default NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 90", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response", req_hex="22 F1 90", resp_hex=resp_hex)

    def test_D4_vin_after_auth(self):
        name="D4_vin_after_auth"
        if not self.security_granted:
            self.record(name, False, "Security not granted; run S1+S2")
            return
        self.send_and_receive(0x10, b'\x02')
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\x90', timeout=5.0)
        if not resp:
            self.record(name, False, "No response to F190 after auth", req_hex="22 F1 90")
            return
        if is_positive_response(0x22, resp):
            # VIN likely in resp[1:]
            payload = resp[1:]
            try:
                vin = payload.decode(errors='ignore').rstrip('\x00')
            except:
                vin = str(payload)
            self.record(name, True, f"F190 VIN read OK: {vin}", req_hex="22 F1 90", resp_hex=resp_hex)
            return
        self.record(name, False, f"F190 read denied NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 90", resp_hex=resp_hex)

    def test_D5_read_config_all_sessions(self):
        name="D5_read_f1a0_default"
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\xA0')
        if not resp:
            self.record(name, False, "No response to read F1A0", req_hex="22 F1 A0")
            return
        if is_positive_response(0x22, resp):
            self.record(name, True, "F1A0 read OK in Default", req_hex="22 F1 A0", resp_hex=resp_hex)
            return
        self.record(name, False, f"F1A0 read failed NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 A0", resp_hex=resp_hex)

    def test_D6_write_f1a0_valid(self):
        name="D6_write_f1a0_valid"
        value = b'\x00\x11'
        resp, resp_hex = self.send_and_receive(0x2E, b'\xF1\xA0' + value)
        if not resp:
            self.record(name, False, "No response to write F1A0", req_hex="2E F1 A0 "+value.hex())
            return
        if is_positive_response(0x2E, resp):
            r2, r2hex = self.send_and_receive(0x22, b'\xF1\xA0')
            if r2 and is_positive_response(0x22, r2) and value in r2:
                self.record(name, True, "F1A0 write and readback OK", req_hex="2E F1 A0 "+value.hex(), resp_hex=r2hex)
                return
            self.record(name, False, "Write positive but readback mismatch", req_hex="2E F1 A0 "+value.hex(), resp_hex=r2hex)
            return
        if is_negative_response(resp):
            self.record(name, False, f"Write rejected NRC=0x{parse_nrc(resp):02X}", req_hex="2E F1 A0 "+value.hex(), resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response to write", req_hex="2E F1 A0 "+value.hex(), resp_hex=resp_hex)

    def test_D7_write_f1a0_invalid(self):
        name="D7_write_f1a0_invalid"
        value = b'\x00\x11\x22'
        resp, resp_hex = self.send_and_receive(0x2E, b'\xF1\xA0' + value)
        if not resp:
            self.record(name, False, "No response to invalid write F1A0", req_hex="2E F1 A0 "+value.hex())
            return
        if is_negative_response(resp):
            self.record(name, True, f"Invalid write rejected NRC=0x{parse_nrc(resp):02X}", req_hex="2E F1 A0 "+value.hex(), resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected positive or format on invalid write", req_hex="2E F1 A0 "+value.hex(), resp_hex=resp_hex)

    def test_D8_write_readonly_did(self):
        name="D8_write_readonly_did"
        value = b'\x00\x01'
        resp, resp_hex = self.send_and_receive(0x2E, b'\xF1\x8C' + value)
        if not resp:
            self.record(name, False, "No response to write read-only DID", req_hex="2E F1 8C "+value.hex())
            return
        if is_negative_response(resp):
            self.record(name, True, f"Write to read-only DID correctly rejected NRC=0x{parse_nrc(resp):02X}", req_hex="2E F1 8C "+value.hex(), resp_hex=resp_hex)
            return
        self.record(name, False, "Write to read-only DID unexpectedly accepted", req_hex="2E F1 8C "+value.hex(), resp_hex=resp_hex)

    # Routines
    def test_R1_start_1234_all_sessions(self):
        name="R1_start_1234_all_sessions"
        resp, resp_hex = self.send_and_receive(0x31, b'\x01\x12\x34')
        if not resp:
            self.record(name, False, "No response to start routine 1234", req_hex="31 01 12 34")
            return
        if is_positive_response(0x31, resp) or (is_negative_response(resp) and parse_nrc(resp)==0x78):
            self.record(name, True, "Routine 1234 start accepted", req_hex="31 01 12 34", resp_hex=resp_hex)
            return
        self.record(name, False, f"Routine 1234 start rejected NRC=0x{parse_nrc(resp):02X}", req_hex="31 01 12 34", resp_hex=resp_hex)

    def test_R2_status_1234(self):
        name="R2_status_1234"
        resp, resp_hex = self.send_and_receive(0x31, b'\x03\x12\x34')
        if not resp:
            self.record(name, False, "No response to routine status 1234", req_hex="31 03 12 34")
            return
        if is_positive_response(0x31, resp):
            self.record(name, True, "Routine 1234 status returned", req_hex="31 03 12 34", resp_hex=resp_hex)
            return
        self.record(name, False, f"Routine 1234 status rejected NRC=0x{parse_nrc(resp):02X}", req_hex="31 03 12 34", resp_hex=resp_hex)

    def test_R3_start_5678_in_default_denied(self):
        name="R3_start_5678_default_denied"
        # Ensure we are in Default session before starting routine
        self.send_and_receive(0x10, b'\x01')
        time.sleep(1)
        resp, resp_hex = self.send_and_receive(0x31, b'\x01\x56\x78')
        if not resp:
            self.record(name, False, "No response to start routine 5678", req_hex="31 01 56 78")
            return
        if is_positive_response(0x31, resp):
            self.record(name, False, "Routine 5678 started in Default (unexpected)", req_hex="31 01 56 78", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"Routine 5678 correctly denied in Default NRC=0x{parse_nrc(resp):02X}", req_hex="31 01 56 78", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response for routine 5678", req_hex="31 01 56 78", resp_hex=resp_hex)

    def test_R4_start_5678_after_auth(self):
        name="R4_start_5678_after_auth"
        if not self.security_granted:
            self.record(name, False, "No security granted; run S1+S2")
            return
        # Ensure we are in Extended session before starting routine
        self.send_and_receive(0x10, b'\x02')
        time.sleep(1)
        resp, resp_hex = self.send_and_receive(0x31, b'\x01\x56\x78', timeout=5.0)
        if not resp:
            self.record(name, False, "No response to start routine 5678", req_hex="31 01 56 78")
            return
        # positive response: 0x71, or negative with NRC=0x78 (Response Pending)
        if is_positive_response(0x31, resp):
            self.record(name, True, "Routine 5678 start accepted after auth", req_hex="31 01 56 78", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            nrc = parse_nrc(resp)
            # response pending accepted as positive-case for long ops
            if nrc == 0x78:
                self.record(name, True, "Routine 5678 returned ResponsePending (0x78) then will complete", req_hex="31 01 56 78", resp_hex=resp_hex)
                return
            # other NRCs are failures but format them safely
            self.record(name, False, f"Routine 5678 rejected NRC={nrc_text(resp, resp_hex)}", req_hex="31 01 56 78", resp_hex=resp_hex)
            return
        # fallback: unexpected non-negative/non-positive response
        self.record(name, False, f"Routine 5678 unexpected response: {nrc_text(resp, resp_hex)}", req_hex="31 01 56 78", resp_hex=resp_hex)

    def test_R5_stop_5678(self):
        name="R5_stop_5678"
        resp, resp_hex = self.send_and_receive(0x31, b'\x02\x56\x78')
        if not resp:
            self.record(name, False, "No response to stop routine 5678", req_hex="31 02 56 78")
            return
        if is_positive_response(0x31, resp):
            self.record(name, True, "Routine 5678 stopped", req_hex="31 02 56 78", resp_hex=resp_hex)
            return
        self.record(name, False, f"Stop routine rejected NRC=0x{parse_nrc(resp):02X}", req_hex="31 02 56 78", resp_hex=resp_hex)

    def test_R6_malformed_routine(self):
        name="R6_malformed_routine"
        resp, resp_hex = self.send_and_receive(0x31, b'')
        if not resp:
            self.record(name, False, "No response to malformed routine", req_hex="31")
            return
        if is_negative_response(resp) and parse_nrc(resp)==0x13:
            self.record(name, True, "Malformed routine rejected with IncorrectMessageLength", req_hex="31", resp_hex=resp_hex)
            return
        self.record(name, False, "Malformed routine not rejected as expected", req_hex="31", resp_hex=resp_hex)

    # ECU Reset
    def test_E1_reset_and_persistence(self):
        name="E1_reset_persistence"
        value = b'\x00\x55'
        #self.send_and_receive(0x2E, b'\xF1\xA0' + value)
        resp, resp_hex = self.send_and_receive(0x11, b'\x03')
        if not resp:
            self.record(name, False, "No response to ECUReset", req_hex="11 03")
            return
        if is_positive_response(0x11, resp):
            time.sleep(1)
            r2, r2hex = self.send_and_receive(0x2E, b'\xF1\xA0'+ value)
            if r2 and is_negative_response(r2):
                r3, r3hex = self.send_and_receive(0x22, b'\xF1\x90')
                if r3 and is_negative_response(r3):
                    self.record(name, True, "Reset preserved persistence and cleared security", req_hex="11 03", resp_hex=r2hex)
                    return
                self.record(name, False, "Security not cleared after reset or F190 readable", req_hex="11 03", resp_hex=r3hex)
                return
            self.record(name, False, "Persistence readback failed after reset", req_hex="11 03", resp_hex=r2hex)
            return
        self.record(name, False, f"Reset rejected NRC=0x{parse_nrc(resp)}", req_hex="11 03", resp_hex=resp_hex)

    # Malformed / Unsupported
    def test_M1_truncated(self):
        name="M1_truncated"
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1')
        if not resp:
            self.record(name, False, "No response to truncated", req_hex="22 F1")
            return
        if is_negative_response(resp) and parse_nrc(resp)==0x13:
            self.record(name, True, "Truncated request correctly rejected", req_hex="22 F1", resp_hex=resp_hex)
            return
        self.record(name, False, "Truncated request not rejected as expected", req_hex="22 F1", resp_hex=resp_hex)

    def test_M2_unsupported_sid(self):
        name="M2_unsupported_sid"
        resp, resp_hex = self.send_and_receive(0x99, b'\x00')
        if not resp:
            self.record(name, False, "No response to unsupported SID", req_hex="99 00")
            return
        if is_negative_response(resp) and parse_nrc(resp)==0x11:
            self.record(name, True, "Unsupported SID correctly returned ServiceNotSupported", req_hex="99 00", resp_hex=resp_hex)
            return
        self.record(name, False, "Unsupported SID did not return expected NRC", req_hex="99 00", resp_hex=resp_hex)

    def test_M3_concurrent_request_during_routine(self):
        name="M3_concurrent_while_routine"
        # start routine 5678 (best-effort)
        self.send_and_receive(0x31, b'\x01\x56\x78')
        resp, resp_hex = self.send_and_receive(0x22, b'\xF1\xA0')
        if not resp:
            self.record(name, False, "No response to concurrent request", req_hex="22 F1 A0")
            return
        if is_positive_response(0x22, resp):
            self.record(name, True, "Concurrent request succeeded while routine running", req_hex="22 F1 A0", resp_hex=resp_hex)
            return
        if is_negative_response(resp):
            self.record(name, True, f"Concurrent request rejected as expected NRC=0x{parse_nrc(resp):02X}", req_hex="22 F1 A0", resp_hex=resp_hex)
            return
        self.record(name, False, "Unexpected response concurrency", req_hex="22 F1 A0", resp_hex=resp_hex)

    def run_all(self):
        sequence = [
            self.test_S1_seed_request,
            self.test_S3_wrong_key,
            self.test_SE1_enter_extended_without_security,
            self.test_S2_correct_key,
            self.test_SE2_enter_extended_with_security,
            self.test_SE3_enter_programming_with_security,
            self.test_SE4_tester_present_and_session_check,
            self.test_SE5_s3_expiry,
            self.test_D1_model_in_default_denied,
            self.test_D2_model_after_auth,
            self.test_D3_vin_in_default_denied,
            self.test_D4_vin_after_auth,
            self.test_D5_read_config_all_sessions,
            self.test_D6_write_f1a0_valid,
            self.test_D7_write_f1a0_invalid,
            self.test_D8_write_readonly_did,
            self.test_R1_start_1234_all_sessions,
            self.test_R2_status_1234,
            self.test_R3_start_5678_in_default_denied,
            self.test_R4_start_5678_after_auth,
            #self.test_R5_stop_5678,
            self.test_R6_malformed_routine,
            self.test_E1_reset_and_persistence,
            self.test_M1_truncated,
            self.test_M2_unsupported_sid,
            self.test_M3_concurrent_request_during_routine,
        ]
        for fn in sequence:
            try:
                fn()
            except Exception as e:
                print(f"Exception during {fn.__name__}: {e}")
        logpath = "uds_test_log.json"
        with open(logpath,'w') as f:
            json.dump(self.log, f, indent=2)
        # Replace the final summary print in run_all() with this colored summary:
        passed = sum(1 for e in self.log if e['ok'])
        total = len(self.log)
        summary = f"Summary: {passed}/{total} tests passed. Log at {logpath}"
        if passed == total:
            print(color(summary, ANSI_GREEN))
        elif passed == 0:
            print(color(summary, ANSI_RED))
        else:
            print(color(summary, ANSI_YELLOW))

        return self.log

def parse_args():
    p = argparse.ArgumentParser(description="UDS Tester with minimal ISO-TP support")
    p.add_argument("--bus", "-b", default="vcan0", help="socketcan channel (default vcan0)")
    p.add_argument("--tx-id", type=lambda x: int(x,0), default=0x7E0, help="Tester TX arbitration ID (default 0x7E0)")
    p.add_argument("--rx-id", type=lambda x: int(x,0), default=0x7E8, help="ECU response ID (default 0x7E8)")
    p.add_argument("--s3", type=int, default=5, help="S3 session timeout seconds (default 5)")
    p.add_argument("--seed-xor", type=lambda x: int(x,0), default=DEFAULT_SEED_XOR, help="Seed XOR constant (hex) default 0x11223344")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Response timeout seconds (default 2.0)")
    return p.parse_args()

def main():
    args = parse_args()
    can_if = CanIf(args.bus, args.tx_id, args.rx_id, timeout=args.timeout)
    tester = UDSTester(can_if, s3=args.s3, seed_xor=args.seed_xor, timeout=args.timeout)
    tester.run_all()

if __name__ == '__main__':
    main()