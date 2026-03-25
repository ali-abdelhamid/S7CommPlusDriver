"""Legitimation — PLC authentication (legacy SHA1-XOR and new AES-CBC).

Ported from Legitimation/Legitimation.cs, LegitimationCrypto.cs,
LegitimationType.cs, and AccessLevel.cs.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from s7commplus.protocol.constants import FunctionCode, Ids, ProtocolVersion
from s7commplus.protocol.errors import (
    ERR_CLI_ACCESS_DENIED,
    ERR_CLI_DEVICE_NOT_SUPPORTED,
    ERR_CLI_FIRMWARE_NOT_SUPPORTED,
    ERR_ISO_INVALID_PDU,
)
from s7commplus.protocol.values import (
    ValueBlob,
    ValueStruct,
    ValueUDInt,
    ValueUSIntArray,
    ValueWString,
)

if TYPE_CHECKING:
    from s7commplus.connection import S7CommPlusConnection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class LegitimationType:
    LEGACY = 1
    NEW = 2


class AccessLevel:
    FULL_ACCESS = 1
    READ_ACCESS = 2
    HMI_ACCESS = 3
    NO_ACCESS = 4


# Regex to parse PAOM string for device/firmware version
_RE_VERSION = re.compile(r"^.*;.*[17]\s?([52]\d\d).+;[VS](\d\.\d)$")


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def _encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-256-CBC with PKCS7 padding."""
    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


# ---------------------------------------------------------------------------
# Payload builder
# ---------------------------------------------------------------------------

def _build_legitimation_payload(password: str, username: str = "") -> bytes:
    """Build the ValueStruct legitimation payload.

    If *username* is provided, uses new-style login (type=2).
    Otherwise, uses legacy login (type=1) with SHA1-hashed password.
    """
    payload = ValueStruct(Ids.LID_LEGITIMATION_PAYLOAD_STRUCT)

    if username:
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_TYPE,
            ValueUDInt(LegitimationType.NEW),
        )
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_USERNAME,
            ValueBlob((0, username.encode("utf-8"), False, 0)),
        )
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_PASSWORD,
            ValueBlob((0, password.encode("utf-8"), False, 0)),
        )
    else:
        hashed_pw = _sha1(password.encode("utf-8"))
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_TYPE,
            ValueUDInt(LegitimationType.LEGACY),
        )
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_USERNAME,
            ValueBlob((0, b"", False, 0)),
        )
        payload.add_element(
            Ids.LID_LEGITIMATION_PAYLOAD_PASSWORD,
            ValueBlob((0, hashed_pw, False, 0)),
        )

    buf = bytearray()
    payload.serialize(buf)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def legitimate(
    conn: S7CommPlusConnection,
    server_session: ValueStruct,
    password: str = "",
    username: str = "",
) -> int:
    """Run the legitimation stage of the connect sequence.

    Parses the server session to determine firmware version, checks the
    current protection level, and authenticates if needed.

    Returns 0 on success or an error code.
    """
    from s7commplus.messages import (
        GetVarSubstreamedRequest,
        GetVarSubstreamedResponse,
    )

    # --- Parse device/firmware version from PAOM string ---
    paom_val = server_session.get_element(Ids.LID_SESSION_VERSION_SYSTEM_PAOM_STRING)
    if paom_val is None or not isinstance(paom_val, ValueWString):
        logger.error("Could not get PAOM string from server session")
        return ERR_CLI_FIRMWARE_NOT_SUPPORTED

    paom_string = paom_val.value
    m = _RE_VERSION.match(paom_string)
    if not m:
        logger.error("Could not extract firmware version from PAOM: %s", paom_string)
        return ERR_CLI_FIRMWARE_NOT_SUPPORTED

    device_version = m.group(1)  # e.g. "500" or "200"
    firmware_str = m.group(2)    # e.g. "3.1"
    fw_parts = firmware_str.split(".")
    fw_ver_no = int(fw_parts[0]) * 100 + int(fw_parts[1])

    # --- Determine auth mode ---
    legacy_legitimation = False

    if device_version.startswith("5"):
        # S7-1500
        if fw_ver_no < 209:
            logger.error("Firmware version %s not supported", firmware_str)
            return ERR_CLI_FIRMWARE_NOT_SUPPORTED
        if fw_ver_no < 301:
            legacy_legitimation = True
    elif "50-0XB0" in paom_string and device_version.startswith("2"):
        # S7-1200 G2 — always new auth
        legacy_legitimation = False
    elif device_version.startswith("2"):
        # S7-1200
        if fw_ver_no < 403:
            logger.error("Firmware version %s not supported", firmware_str)
            return ERR_CLI_FIRMWARE_NOT_SUPPORTED
        if fw_ver_no < 407:
            legacy_legitimation = True
    else:
        logger.error("Device version %s not supported", device_version)
        return ERR_CLI_DEVICE_NOT_SUPPORTED

    # --- Read effective protection level ---
    req = GetVarSubstreamedRequest(ProtocolVersion.V2)
    req.in_object_id = conn.session_id
    req.session_id = conn.session_id
    req.address = Ids.EFFECTIVE_PROTECTION_LEVEL

    res = conn.send_request(req)
    if res != 0:
        return res

    pdu_data = conn.wait_for_response()
    if pdu_data is None:
        return conn.last_error or ERR_ISO_INVALID_PDU

    resp = GetVarSubstreamedResponse.from_pdu(pdu_data)
    if resp is None:
        logger.error("GetVarSubstreamed (protection level) failed")
        return ERR_ISO_INVALID_PDU

    access_level = resp.value.value if resp.value else 0

    # --- Authenticate if needed ---
    if access_level > AccessLevel.FULL_ACCESS and password:
        if legacy_legitimation:
            return _legitimate_legacy(conn, password)
        else:
            return _legitimate_new(conn, password, username)
    elif access_level > AccessLevel.FULL_ACCESS:
        logger.warning("Access level is not full-access but no password set")

    return 0


# ---------------------------------------------------------------------------
# New legitimation (AES-CBC, firmware >= 3.1)
# ---------------------------------------------------------------------------

def _legitimate_new(
    conn: S7CommPlusConnection,
    password: str,
    username: str = "",
) -> int:
    """New-style authentication using AES-256-CBC encrypted payload."""
    from s7commplus.messages import (
        GetVarSubstreamedRequest,
        GetVarSubstreamedResponse,
        SetVariableRequest,
        SetVariableResponse,
    )

    # Get challenge
    req = GetVarSubstreamedRequest(ProtocolVersion.V2)
    req.in_object_id = conn.session_id
    req.session_id = conn.session_id
    req.address = Ids.SERVER_SESSION_REQUEST

    res = conn.send_request(req)
    if res != 0:
        return res

    pdu_data = conn.wait_for_response()
    if pdu_data is None:
        return conn.last_error or ERR_ISO_INVALID_PDU

    resp = GetVarSubstreamedResponse.from_pdu(pdu_data)
    if resp is None:
        logger.error("GetVarSubstreamed (challenge) failed")
        return ERR_ISO_INVALID_PDU

    challenge = resp.value.value  # list of bytes from ValueUSIntArray

    # Get or roll OMS exporter secret
    if conn.oms_secret is None or len(conn.oms_secret) != 32:
        conn.oms_secret = conn.client.get_oms_exporter_secret()
        if conn.oms_secret is None:
            logger.error("Could not get OMS exporter secret")
            return ERR_ISO_INVALID_PDU

    # Roll key
    key = _sha256(conn.oms_secret)
    conn.oms_secret = key

    # IV = first 16 bytes of challenge
    iv = bytes(challenge[:16])

    # Encrypt payload
    payload = _build_legitimation_payload(password, username)
    encrypted = _encrypt_aes_cbc(payload, key, iv)

    # Send challenge response
    set_req = SetVariableRequest(ProtocolVersion.V2)
    set_req.in_object_id = conn.session_id
    set_req.session_id = conn.session_id
    set_req.address = Ids.LEGITIMATE
    set_req.value = ValueBlob((0, encrypted, False, 0))

    res = conn.send_request(set_req)
    if res != 0:
        return res

    pdu_data = conn.wait_for_response()
    if pdu_data is None:
        return conn.last_error or ERR_ISO_INVALID_PDU

    set_resp = SetVariableResponse.from_pdu(pdu_data)
    if set_resp is None:
        logger.error("SetVariable (legitimate) response failed")
        return ERR_ISO_INVALID_PDU

    # Check result — negative return value means access denied
    error_code = set_resp.return_value & 0xFFFF
    if error_code > 0x7FFF:  # negative as int16
        logger.error("Legitimation: access denied")
        return ERR_CLI_ACCESS_DENIED

    return 0


# ---------------------------------------------------------------------------
# Legacy legitimation (SHA1 XOR, firmware < 3.1)
# ---------------------------------------------------------------------------

def _legitimate_legacy(conn: S7CommPlusConnection, password: str) -> int:
    """Legacy authentication using SHA1(password) XOR challenge."""
    from s7commplus.messages import (
        GetVarSubstreamedRequest,
        GetVarSubstreamedResponse,
        SetVariableRequest,
        SetVariableResponse,
    )

    # Get challenge
    req = GetVarSubstreamedRequest(ProtocolVersion.V2)
    req.in_object_id = conn.session_id
    req.session_id = conn.session_id
    req.address = Ids.SERVER_SESSION_REQUEST

    res = conn.send_request(req)
    if res != 0:
        return res

    pdu_data = conn.wait_for_response()
    if pdu_data is None:
        return conn.last_error or ERR_ISO_INVALID_PDU

    resp = GetVarSubstreamedResponse.from_pdu(pdu_data)
    if resp is None:
        logger.error("GetVarSubstreamed (legacy challenge) failed")
        return ERR_ISO_INVALID_PDU

    challenge = resp.value.value  # list of bytes

    # SHA1(password) XOR challenge
    hashed = _sha1(password.encode("utf-8"))
    if len(hashed) != len(challenge):
        logger.error("Challenge length mismatch: %d vs %d", len(hashed), len(challenge))
        return ERR_ISO_INVALID_PDU

    response_bytes = bytes(h ^ c for h, c in zip(hashed, challenge))

    # Send response
    set_req = SetVariableRequest(ProtocolVersion.V2)
    set_req.in_object_id = conn.session_id
    set_req.session_id = conn.session_id
    set_req.address = Ids.SERVER_SESSION_RESPONSE
    set_req.value = ValueUSIntArray(list(response_bytes))

    res = conn.send_request(set_req)
    if res != 0:
        return res

    pdu_data = conn.wait_for_response()
    if pdu_data is None:
        return conn.last_error or ERR_ISO_INVALID_PDU

    set_resp = SetVariableResponse.from_pdu(pdu_data)
    if set_resp is None:
        logger.error("SetVariable (legacy legitimate) response failed")
        return ERR_ISO_INVALID_PDU

    error_code = set_resp.return_value & 0xFFFF
    if error_code > 0x7FFF:
        logger.error("Legacy legitimation: access denied")
        return ERR_CLI_ACCESS_DENIED

    return 0
