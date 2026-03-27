"""SystemEvent — extended keep-alive telegrams (TIA V14+).

Values in SystemEvent do NOT use VLQ encoding — all widths are fixed.
"""

from __future__ import annotations

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import ProtocolVersion, Datatype, Ids
from s7commplus.protocol.values import PValue, ValueStruct, ValueLInt


class SystemEvent:
    """Extended keep-alive (16 or 22 bytes payload).

    May contain either a struct with status data or a raw string like
    ``"LOGOUT"`` after DeleteObject.
    """

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a SystemEvent with default values.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.reserved1: int = 0
        self.confirmed_bytes: int = 0
        self.reserved2: int = 0
        self.reserved3: int = 0
        self.is_data: bool = False
        self.data: PValue | None = None
        self.is_message: bool = False
        self.message: str = ""

    def deserialize(self, data: bytes, offset: int) -> int:

        """Deserialize this system event from wire data.

        Values use fixed-width encoding (no VLQ).

        Args:
            data: Source byte buffer.
            offset: Position to read from.

        Returns:
            Number of bytes consumed.
        """
        start = offset
        self.reserved1, n = s7p.decode_uint32(data, offset); offset += n
        self.confirmed_bytes, n = s7p.decode_uint32(data, offset); offset += n
        self.reserved2, n = s7p.decode_uint32(data, offset); offset += n
        self.reserved3, n = s7p.decode_uint32(data, offset); offset += n

        remaining = len(data) - offset

        if remaining >= 4:
            peek_type, _ = s7p.decode_uint32(data, offset)
            if peek_type == Datatype.STRUCT:
                self.is_data = True
                self.is_message = False
                self.data, n = PValue.deserialize(data, offset, disable_vlq=True)
                offset += n
                remaining = len(data) - offset

        if not self.is_data and remaining > 0:
            self.is_message = True
            self.message, n = s7p.decode_wstring(data, offset, remaining)
            offset += n

        return offset - start

    def is_fatal_error(self) -> bool:
        """Check if this event indicates a fatal connection error."""
        if self.data is not None and isinstance(self.data, ValueStruct):
            retval_elem = self.data.get_element(Ids.RETURN_VALUE)
            if retval_elem is not None and isinstance(retval_elem, ValueLInt):
                return retval_elem.value < 0
            return True
        return False

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> SystemEvent | None:

        """Construct a SystemEvent from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated :class:`SystemEvent`, or ``None`` if version mismatch.
        """
        proto_ver, n = s7p.decode_byte(data, offset); offset += n
        if proto_ver != ProtocolVersion.SYSTEM_EVENT:
            return None
        evt = cls(proto_ver)
        evt.deserialize(data, offset)
        return evt
