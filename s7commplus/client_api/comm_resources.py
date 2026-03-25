"""CommResources — read PLC system limits and free resource counters.

Ported from Core/CommRessources.cs.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from s7commplus.connection import S7CommPlusConnection

from s7commplus.protocol.constants import Ids
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import ValueDInt


class CommResources:
    """PLC resource limits read via ObjectRoot/SystemLimits."""

    def __init__(self) -> None:
        self.tags_per_read_max: int = 20
        self.tags_per_write_max: int = 20
        self.plc_attributes_max: int = 0
        self.plc_attributes_free: int = 0
        self.plc_subscriptions_max: int = 0
        self.plc_subscriptions_free: int = 0
        self.subscription_memory_max: int = 0
        self.subscription_memory_free: int = 0

    def read_max(self, conn: S7CommPlusConnection) -> int:
        """Read system-limit maximums from the PLC.

        Reads 5 addresses from ObjectRoot/SystemLimits:
          LID 1000 = TagsPerReadRequestMax
          LID 1001 = TagsPerWriteRequestMax
          LID 0    = PlcSubscriptionsMax
          LID 1    = PlcAttributesMax
          LID 2    = SubscriptionMemoryMax
        """
        addresses = []
        for lid in (1000, 1001, 0, 1, 2):
            addr = ItemAddress(area=Ids.OBJECT_ROOT, sub_area=Ids.SYSTEM_LIMITS)
            addr.lid = [lid]
            addresses.append(addr)

        values, errors, res = conn.read_values(addresses)
        if res != 0:
            return res

        setters = [
            lambda v: setattr(self, 'tags_per_read_max', v),
            lambda v: setattr(self, 'tags_per_write_max', v),
            lambda v: setattr(self, 'plc_subscriptions_max', v),
            lambda v: setattr(self, 'plc_attributes_max', v),
            lambda v: setattr(self, 'subscription_memory_max', v),
        ]

        for i, setter in enumerate(setters):
            if i < len(values) and values[i] is not None and errors[i] == 0:
                if isinstance(values[i], ValueDInt):
                    setter(values[i].value)

        return res

    def read_free(self, conn: S7CommPlusConnection) -> int:
        """Read free resource counters from the PLC.

        Reads 3 addresses from ObjectRoot/FreeItems:
          LID 0 = PlcSubscriptionsFree
          LID 1 = PlcAttributesFree
          LID 2 = SubscriptionMemoryFree
        """
        addresses = []
        for lid in (0, 1, 2):
            addr = ItemAddress(area=Ids.OBJECT_ROOT, sub_area=Ids.FREE_ITEMS)
            addr.lid = [lid]
            addresses.append(addr)

        values, errors, res = conn.read_values(addresses)
        if res != 0:
            return res

        setters = [
            lambda v: setattr(self, 'plc_subscriptions_free', v),
            lambda v: setattr(self, 'plc_attributes_free', v),
            lambda v: setattr(self, 'subscription_memory_free', v),
        ]

        for i, setter in enumerate(setters):
            if i < len(values) and values[i] is not None and errors[i] == 0:
                if isinstance(values[i], ValueDInt):
                    setter(values[i].value)

        return res
