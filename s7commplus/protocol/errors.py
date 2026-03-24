"""
Error codes and exception classes for S7CommPlus.

Ported from S7Consts.cs (Net/).
"""


class S7CommPlusError(Exception):
    """Base exception for all S7CommPlus errors."""

    def __init__(self, code: int, message: str = ""):
        self.code = code
        self.message = message or error_text(code)
        super().__init__(self.message)


class TCPError(S7CommPlusError):
    pass


class ISOError(S7CommPlusError):
    pass


class ClientError(S7CommPlusError):
    pass


class OpenSSLError(S7CommPlusError):
    pass


# ---------------------------------------------------------------------------
# Error code constants  (S7Consts.cs)
# ---------------------------------------------------------------------------

# TCP errors
ERR_TCP_SOCKET_CREATION = 0x00000001
ERR_TCP_CONNECTION_TIMEOUT = 0x00000002
ERR_TCP_CONNECTION_FAILED = 0x00000003
ERR_TCP_RECEIVE_TIMEOUT = 0x00000004
ERR_TCP_DATA_RECEIVE = 0x00000005
ERR_TCP_SEND_TIMEOUT = 0x00000006
ERR_TCP_DATA_SEND = 0x00000007
ERR_TCP_CONNECTION_RESET = 0x00000008
ERR_TCP_NOT_CONNECTED = 0x00000009
ERR_TCP_UNREACHABLE_HOST = 0x00002751

# ISO errors
ERR_ISO_CONNECT = 0x00010000
ERR_ISO_INVALID_PDU = 0x00030000
ERR_ISO_INVALID_DATA_SIZE = 0x00040000

# Client errors
ERR_CLI_NEGOTIATING_PDU = 0x00100000
ERR_CLI_INVALID_PARAMS = 0x00200000
ERR_CLI_JOB_PENDING = 0x00300000
ERR_CLI_TOO_MANY_ITEMS = 0x00400000
ERR_CLI_INVALID_WORD_LEN = 0x00500000
ERR_CLI_PARTIAL_DATA_WRITTEN = 0x00600000
ERR_CLI_SIZE_OVER_PDU = 0x00700000
ERR_CLI_INVALID_PLC_ANSWER = 0x00800000
ERR_CLI_ADDRESS_OUT_OF_RANGE = 0x00900000
ERR_CLI_INVALID_TRANSPORT_SIZE = 0x00A00000
ERR_CLI_WRITE_DATA_SIZE_MISMATCH = 0x00B00000
ERR_CLI_ITEM_NOT_AVAILABLE = 0x00C00000
ERR_CLI_INVALID_VALUE = 0x00D00000
ERR_CLI_CANNOT_START_PLC = 0x00E00000
ERR_CLI_ALREADY_RUN = 0x00F00000
ERR_CLI_CANNOT_STOP_PLC = 0x01000000
ERR_CLI_CANNOT_COPY_RAM_TO_ROM = 0x01100000
ERR_CLI_CANNOT_COMPRESS = 0x01200000
ERR_CLI_ALREADY_STOP = 0x01300000
ERR_CLI_FUN_NOT_AVAILABLE = 0x01400000
ERR_CLI_UPLOAD_SEQUENCE_FAILED = 0x01500000
ERR_CLI_INVALID_DATA_SIZE_RECVD = 0x01600000
ERR_CLI_INVALID_BLOCK_TYPE = 0x01700000
ERR_CLI_INVALID_BLOCK_NUMBER = 0x01800000
ERR_CLI_INVALID_BLOCK_SIZE = 0x01900000
ERR_CLI_NEED_PASSWORD = 0x01D00000
ERR_CLI_INVALID_PASSWORD = 0x01E00000
ERR_CLI_ACCESS_DENIED = 0x01E10000
ERR_CLI_NO_PASSWORD_TO_SET_OR_CLEAR = 0x01F00000
ERR_CLI_JOB_TIMEOUT = 0x02000000
ERR_CLI_PARTIAL_DATA_READ = 0x02100000
ERR_CLI_BUFFER_TOO_SMALL = 0x02200000
ERR_CLI_FUNCTION_REFUSED = 0x02300000
ERR_CLI_DESTROYING = 0x02400000
ERR_CLI_INVALID_PARAM_NUMBER = 0x02500000
ERR_CLI_CANNOT_CHANGE_PARAM = 0x02600000
ERR_CLI_FUNCTION_NOT_IMPLEMENTED = 0x02700000
ERR_CLI_FIRMWARE_NOT_SUPPORTED = 0x02800000
ERR_CLI_DEVICE_NOT_SUPPORTED = 0x02900000

# OpenSSL errors
ERR_OPENSSL = 0x03100000


# ---------------------------------------------------------------------------
# Error text lookup
# ---------------------------------------------------------------------------

_ERROR_TEXTS: dict[int, str] = {
    0: "OK",
    ERR_TCP_SOCKET_CREATION: "SYS : Error creating the Socket",
    ERR_TCP_CONNECTION_TIMEOUT: "TCP : Connection Timeout",
    ERR_TCP_CONNECTION_FAILED: "TCP : Connection Error",
    ERR_TCP_RECEIVE_TIMEOUT: "TCP : Data receive Timeout",
    ERR_TCP_DATA_RECEIVE: "TCP : Error receiving Data",
    ERR_TCP_SEND_TIMEOUT: "TCP : Data send Timeout",
    ERR_TCP_DATA_SEND: "TCP : Error sending Data",
    ERR_TCP_CONNECTION_RESET: "TCP : Connection reset by the Peer",
    ERR_TCP_NOT_CONNECTED: "CLI : Client not connected",
    ERR_TCP_UNREACHABLE_HOST: "TCP : Unreachable host",
    ERR_ISO_CONNECT: "ISO : Connection Error",
    ERR_ISO_INVALID_PDU: "ISO : Invalid PDU received",
    ERR_ISO_INVALID_DATA_SIZE: "ISO : Invalid Buffer passed to Send/Receive",
    ERR_CLI_NEGOTIATING_PDU: "CLI : Error in PDU negotiation",
    ERR_CLI_INVALID_PARAMS: "CLI : invalid param(s) supplied",
    ERR_CLI_JOB_PENDING: "CLI : Job pending",
    ERR_CLI_TOO_MANY_ITEMS: "CLI : too many items (>20) in multi read/write",
    ERR_CLI_INVALID_WORD_LEN: "CLI : invalid WordLength",
    ERR_CLI_PARTIAL_DATA_WRITTEN: "CLI : Partial data written",
    ERR_CLI_SIZE_OVER_PDU: "CPU : total data exceeds the PDU size",
    ERR_CLI_INVALID_PLC_ANSWER: "CLI : invalid CPU answer",
    ERR_CLI_ADDRESS_OUT_OF_RANGE: "CPU : Address out of range",
    ERR_CLI_INVALID_TRANSPORT_SIZE: "CPU : Invalid Transport size",
    ERR_CLI_WRITE_DATA_SIZE_MISMATCH: "CPU : Data size mismatch",
    ERR_CLI_ITEM_NOT_AVAILABLE: "CPU : Item not available",
    ERR_CLI_INVALID_VALUE: "CPU : Invalid value supplied",
    ERR_CLI_CANNOT_START_PLC: "CPU : Cannot start PLC",
    ERR_CLI_ALREADY_RUN: "CPU : PLC already RUN",
    ERR_CLI_CANNOT_STOP_PLC: "CPU : Cannot stop PLC",
    ERR_CLI_CANNOT_COPY_RAM_TO_ROM: "CPU : Cannot copy RAM to ROM",
    ERR_CLI_CANNOT_COMPRESS: "CPU : Cannot compress",
    ERR_CLI_ALREADY_STOP: "CPU : PLC already STOP",
    ERR_CLI_FUN_NOT_AVAILABLE: "CPU : Function not available",
    ERR_CLI_UPLOAD_SEQUENCE_FAILED: "CPU : Upload sequence failed",
    ERR_CLI_INVALID_DATA_SIZE_RECVD: "CLI : Invalid data size received",
    ERR_CLI_INVALID_BLOCK_TYPE: "CLI : Invalid block type",
    ERR_CLI_INVALID_BLOCK_NUMBER: "CLI : Invalid block number",
    ERR_CLI_INVALID_BLOCK_SIZE: "CLI : Invalid block size",
    ERR_CLI_NEED_PASSWORD: "CPU : Function not authorized for current protection level",
    ERR_CLI_INVALID_PASSWORD: "CPU : Invalid password",
    ERR_CLI_ACCESS_DENIED: "CPU : Access denied",
    ERR_CLI_NO_PASSWORD_TO_SET_OR_CLEAR: "CPU : No password to set or clear",
    ERR_CLI_JOB_TIMEOUT: "CLI : Job Timeout",
    ERR_CLI_FUNCTION_REFUSED: "CLI : function refused by CPU (Unknown error)",
    ERR_CLI_PARTIAL_DATA_READ: "CLI : Partial data read",
    ERR_CLI_BUFFER_TOO_SMALL: "CLI : The buffer supplied is too small",
    ERR_CLI_DESTROYING: "CLI : Cannot perform (destroying)",
    ERR_CLI_INVALID_PARAM_NUMBER: "CLI : Invalid Param Number",
    ERR_CLI_CANNOT_CHANGE_PARAM: "CLI : Cannot change this param now",
    ERR_CLI_FUNCTION_NOT_IMPLEMENTED: "CLI : Function not implemented",
    ERR_CLI_FIRMWARE_NOT_SUPPORTED: "CLI : Firmware not supported",
    ERR_CLI_DEVICE_NOT_SUPPORTED: "CLI : Device type not supported",
    ERR_OPENSSL: "CLI : OpenSSL error",
}


def error_text(code: int) -> str:
    """Return human-readable text for an error code."""
    return _ERROR_TEXTS.get(code, f"CLI : Unknown error (0x{code:08x})")


def check_error(code: int) -> None:
    """Raise an appropriate exception if *code* is non-zero."""
    if code == 0:
        return
    msg = error_text(code)
    if code <= 0x00002751:
        raise TCPError(code, msg)
    elif code <= 0x00040000:
        raise ISOError(code, msg)
    elif code == ERR_OPENSSL:
        raise OpenSSLError(code, msg)
    else:
        raise ClientError(code, msg)
