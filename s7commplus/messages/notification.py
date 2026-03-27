"""Notification — asynchronous variable change notifications from PLC."""

from __future__ import annotations

from datetime import datetime, timezone

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import Opcode
from s7commplus.protocol.pobject import PObject, decode_object_list
from s7commplus.protocol.values import PValue


class Notification:
    """Asynchronous notification from PLC.

    Carries subscription-based value change data, error return values,
    and optionally alarm objects (P2).
    """

    def __init__(self, protocol_version: int = 0) -> None:

        """Initialize a Notification with default values.

        Args:
            protocol_version: Wire protocol version.
        """
        self.protocol_version = protocol_version
        self.subscription_object_id: int = 0
        self.unknown2: int = 0
        self.unknown3: int = 0
        self.unknown4: int = 0
        self.notification_credit_tick: int = 0
        self.notification_sequence_number: int = 0
        self.subscription_change_counter: int = 0
        self.add1_timestamp: datetime | None = None
        self.add1_subscription_change_counter: int = 0
        self.values: dict[int, PValue] = {}
        self.return_values: dict[int, int] = {}
        # Alarm (P2) fields
        self.p2_subscription_object_id: int = 0
        self.p2_unknown1: int = 0
        self.p2_return_value: int = 0
        self.p2_objects: list[PObject] = []

    def deserialize(self, data: bytes, offset: int) -> int:

        """Deserialize this notification from wire data.

        Args:
            data: Source byte buffer.
            offset: Position to read from.

        Returns:
            Number of bytes consumed.
        """
        start = offset

        self.subscription_object_id, n = s7p.decode_uint32(data, offset); offset += n
        self.unknown2, n = s7p.decode_uint16(data, offset); offset += n
        self.unknown3, n = s7p.decode_uint16(data, offset); offset += n
        self.unknown4, n = s7p.decode_uint16(data, offset); offset += n

        self.notification_credit_tick, n = s7p.decode_byte(data, offset); offset += n
        self.notification_sequence_number, n = s7p.decode_uint32_vlq(data, offset); offset += n

        subscrccnt, n = s7p.decode_byte(data, offset); offset += n
        if subscrccnt > 0:
            self.subscription_change_counter = subscrccnt
        else:
            # Newer 1500 FW: 8-byte UTC timestamp follows (rewind 1 byte)
            offset -= 1
            ts_raw, n = s7p.decode_uint64(data, offset); offset += n
            # Convert 100ns ticks since 0001-01-01 to Python datetime
            epoch_ticks = 621355968000000000  # .NET epoch offset
            us = (ts_raw - epoch_ticks) // 10 if ts_raw > epoch_ticks else 0
            self.add1_timestamp = datetime(1970, 1, 1, tzinfo=timezone.utc) + \
                __import__("datetime").timedelta(microseconds=us)
            self.add1_subscription_change_counter, n = s7p.decode_byte(data, offset)
            offset += n

        # Value / error return value loop
        while offset < len(data):
            item_rv, n = s7p.decode_byte(data, offset); offset += n
            if item_rv == 0x00:
                break
            elif item_rv == 0x92:
                itemref, n = s7p.decode_uint32(data, offset); offset += n
                val, n = PValue.deserialize(data, offset); offset += n
                self.values[itemref] = val
            elif item_rv == 0x9B:
                itemref, n = s7p.decode_uint32_vlq(data, offset); offset += n
                val, n = PValue.deserialize(data, offset); offset += n
                self.values[itemref] = val
            elif item_rv == 0x9C:
                _, n = s7p.decode_uint32(data, offset); offset += n  # skip
            elif item_rv in (0x13, 0x03):
                itemref, n = s7p.decode_uint32(data, offset); offset += n
                self.return_values[itemref] = item_rv
            else:
                break

        # Alarm object (P2) — optional
        if offset < len(data):
            peek, _ = s7p.decode_byte(data, offset)
            if peek != 0:
                self.p2_subscription_object_id, n = s7p.decode_uint32(data, offset); offset += n
                self.p2_unknown1, n = s7p.decode_uint16(data, offset); offset += n
                self.p2_return_value, n = s7p.decode_byte(data, offset); offset += n
                if self.p2_return_value == 0x81:
                    self.p2_objects, n = decode_object_list(data, offset)
                    offset += n

        return offset - start

    @classmethod
    def from_pdu(cls, data: bytes, offset: int = 0) -> Notification | None:

        """Construct a Notification from a complete PDU.

        Args:
            data: Raw PDU bytes.
            offset: Starting offset.

        Returns:
            Populated :class:`Notification`, or ``None`` if opcode mismatch.
        """
        proto_ver, n = s7p.decode_byte(data, offset); offset += n
        opcode, n = s7p.decode_byte(data, offset); offset += n
        if opcode != Opcode.NOTIFICATION:
            return None
        notif = cls(proto_ver)
        notif.deserialize(data, offset)
        return notif
