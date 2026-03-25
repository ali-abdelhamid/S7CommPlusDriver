"""
Protocol objects — PObject, PVartypeList, PVarnameList, ItemAddress.

Ported from PObject.cs, PVartypeList.cs, PVarnameList.cs, ItemAddress.cs,
and POffsetInfoType.cs.
"""

from __future__ import annotations

from typing import Any

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import ElementID, Ids, Datatype


# ===========================================================================
# PObject — the core protocol object
# ===========================================================================

class PObject:
    """S7CommPlus protocol object.

    Fields mirror the C# PObject: RelationId, ClassId, ClassFlags,
    AttributeId, Attributes, Objects, Relations, VartypeList, VarnameList.
    """

    def __init__(self, rid: int = 0, cls_id: int = 0, aid: int = 0) -> None:
        self.relation_id: int = rid
        self.class_id: int = cls_id
        self.class_flags: int = 0
        self.attribute_id: int = aid
        self.attributes: dict[int, Any] = {}       # uint32 → PValue
        self.objects: dict[tuple[int, int], PObject] = {}  # (class_id, rel_id) → PObject
        self.relations: dict[int, int] = {}         # uint32 → uint32
        self.vartype_list: PVartypeList | None = None
        self.varname_list: PVarnameList | None = None

    def add_attribute(self, attr_id: int, value: Any) -> None:
        self.attributes[attr_id] = value

    def get_attribute(self, attr_id: int) -> Any:
        return self.attributes.get(attr_id)

    def add_relation(self, rel_id: int, value: int) -> None:
        self.relations[rel_id] = value

    def add_object(self, obj: PObject) -> None:
        key = (obj.class_id, obj.relation_id)
        self.objects[key] = obj

    def get_object(self, class_id: int, rel_id: int) -> PObject | None:
        return self.objects.get((class_id, rel_id))

    def get_objects_by_class(self, class_id: int) -> list[PObject]:
        return [o for (cid, _), o in self.objects.items() if cid == class_id]

    def get_all_objects(self) -> list[PObject]:
        return list(self.objects.values())

    def serialize(self, buf: bytearray) -> int:
        ret = 0
        ret += s7p.encode_byte(buf, ElementID.START_OF_OBJECT)
        ret += s7p.encode_uint32(buf, self.relation_id)
        ret += s7p.encode_uint32_vlq(buf, self.class_id)
        ret += s7p.encode_uint32_vlq(buf, self.class_flags)
        ret += s7p.encode_uint32_vlq(buf, self.attribute_id)
        for attr_id, value in self.attributes.items():
            ret += s7p.encode_byte(buf, ElementID.ATTRIBUTE)
            ret += s7p.encode_uint32_vlq(buf, attr_id)
            ret += value.serialize(buf)
        for obj in self.objects.values():
            ret += obj.serialize(buf)
        for rel_id, rel_val in self.relations.items():
            ret += s7p.encode_byte(buf, ElementID.RELATION)
            ret += s7p.encode_uint32_vlq(buf, rel_id)
            ret += s7p.encode_uint32(buf, rel_val)
        ret += s7p.encode_byte(buf, ElementID.TERMINATING_OBJECT)
        return ret


# ===========================================================================
# PVartypeList — tag description list
# ===========================================================================

class OffsetInfo:
    """Generic offset info parsed from a vartype list element."""

    # Offset info type constants
    FB_ARRAY = 0
    STRUCT_ELEM_STD = 1; STD = 8
    STRUCT_ELEM_STRING = 2; STRING = 9
    STRUCT_ELEM_ARRAY_1DIM = 3; ARRAY_1DIM = 10
    STRUCT_ELEM_ARRAY_MDIM = 4; ARRAY_MDIM = 11
    STRUCT_ELEM_STRUCT = 5; STRUCT = 12
    STRUCT_ELEM_STRUCT_1DIM = 6; STRUCT_1DIM = 13
    STRUCT_ELEM_STRUCT_MDIM = 7; STRUCT_MDIM = 14
    FB_SFB = 15

    def __init__(self) -> None:
        self.offset_type: int = 0
        self.optimized_address: int = 0
        self.nonoptimized_address: int = 0
        self.relation_id: int = 0
        self.array_lower_bounds: int = 0
        self.array_element_count: int = 0
        self.mdim_lower_bounds: list[int] = []
        self.mdim_element_counts: list[int] = []
        self.extra: dict[str, int] = {}

    def has_relation(self) -> bool:
        return self.offset_type in (0, 5, 6, 7, 12, 13, 14, 15)

    def is_1dim(self) -> bool:
        return self.offset_type in (3, 6, 10, 13)

    def is_mdim(self) -> bool:
        return self.offset_type in (4, 7, 11, 14)


class VartypeElement:
    """One element in a PVartypeList."""

    # attribute_flags masks
    ATTR_OFFSETINFOTYPE = 0xF000
    ATTR_HMI_VISIBLE = 0x0800
    ATTR_HMI_READONLY = 0x0400
    ATTR_HMI_ACCESSIBLE = 0x0200
    ATTR_OPTIMIZED_ACCESS = 0x0080
    ATTR_SECTION = 0x0070
    ATTR_BITOFFSET = 0x0007

    # bitoffsetinfo_flags masks
    BITINFO_RETAIN = 0x80
    BITINFO_NONOPT_BITOFFSET = 0x70
    BITINFO_CLASSIC = 0x08
    BITINFO_OPT_BITOFFSET = 0x07

    def __init__(self) -> None:
        self.lid: int = 0
        self.symbol_crc: int = 0
        self.softdatatype: int = 0
        self.attribute_flags: int = 0
        self.bitoffsetinfo_flags: int = 0
        self.offset_info: OffsetInfo | None = None

    def get_attribute_bitoffset(self) -> int:
        return self.attribute_flags & self.ATTR_BITOFFSET

    def get_attribute_section(self) -> int:
        return (self.attribute_flags & self.ATTR_SECTION) >> 4

    def get_bitoffsetinfo_flag_classic(self) -> bool:
        return (self.bitoffsetinfo_flags & self.BITINFO_CLASSIC) != 0

    def get_bitoffsetinfo_nonoptimized_bitoffset(self) -> int:
        return (self.bitoffsetinfo_flags & self.BITINFO_NONOPT_BITOFFSET) >> 4

    def get_bitoffsetinfo_optimized_bitoffset(self) -> int:
        return self.bitoffsetinfo_flags & self.BITINFO_OPT_BITOFFSET


def _deserialize_offset_info(data: bytes, offset: int, oi_type: int) -> tuple[OffsetInfo, int]:
    """Deserialize an OffsetInfo based on its type."""
    start = offset
    oi = OffsetInfo()
    oi.offset_type = oi_type

    if oi_type in (1, 8):
        # Std — two uint16 LE values, order swapped between old (1) and new (8)
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        if oi_type == 8:
            oi.optimized_address = v1
            oi.nonoptimized_address = v2
        else:
            oi.nonoptimized_address = v1
            oi.optimized_address = v2
    elif oi_type in (2, 9):
        # String
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.extra["max_length"] = v1
        oi.extra["max_length_header"] = v2
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
    elif oi_type in (3, 10):
        # Array1Dim
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.extra["unspecified_offsetinfo1"] = v1  # used for String/WString array element size
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.array_lower_bounds, n = s7p.decode_int32_le(data, offset); offset += n
        oi.array_element_count, n = s7p.decode_uint32_le(data, offset); offset += n
    elif oi_type in (4, 11):
        # ArrayMDim
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.extra["unspecified_offsetinfo1"] = v1  # used for String/WString array element size
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.array_lower_bounds, n = s7p.decode_int32_le(data, offset); offset += n
        oi.array_element_count, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.mdim_lower_bounds = []
        for _ in range(6):
            v, n = s7p.decode_int32_le(data, offset); offset += n
            oi.mdim_lower_bounds.append(v)
        oi.mdim_element_counts = []
        for _ in range(6):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.mdim_element_counts.append(v)
    elif oi_type in (5, 12):
        # Struct
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.relation_id, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("info4", "info5", "info6", "info7"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
    elif oi_type in (6, 13):
        # Struct1Dim
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.array_lower_bounds, n = s7p.decode_int32_le(data, offset); offset += n
        oi.array_element_count, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("nonopt_struct_size", "opt_struct_size"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
        oi.relation_id, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("info4", "info5", "info6", "info7"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
    elif oi_type in (7, 14):
        # StructMDim
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.array_lower_bounds, n = s7p.decode_int32_le(data, offset); offset += n
        oi.array_element_count, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.mdim_lower_bounds = []
        for _ in range(6):
            v, n = s7p.decode_int32_le(data, offset); offset += n
            oi.mdim_lower_bounds.append(v)
        oi.mdim_element_counts = []
        for _ in range(6):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.mdim_element_counts.append(v)
        for name in ("nonopt_struct_size", "opt_struct_size"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
        oi.relation_id, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("info4", "info5", "info6", "info7"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
    elif oi_type == 0:
        # FbArray
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.relation_id, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("info4", "info5", "info6", "info7",
                      "retain_offset", "volatile_offset",
                      "array_count", "classic_size", "retain_size", "volatile_size"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v
        oi.mdim_lower_bounds = []
        for _ in range(6):
            v, n = s7p.decode_int32_le(data, offset); offset += n
            oi.mdim_lower_bounds.append(v)
        oi.mdim_element_counts = []
        for _ in range(6):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.mdim_element_counts.append(v)
    elif oi_type == 15:
        # FbSfb
        v1, n = s7p.decode_uint16_le(data, offset); offset += n
        v2, n = s7p.decode_uint16_le(data, offset); offset += n
        oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
        oi.relation_id, n = s7p.decode_uint32_le(data, offset); offset += n
        for name in ("info4", "info5", "info6", "info7",
                      "retain_offset", "volatile_offset"):
            v, n = s7p.decode_uint32_le(data, offset); offset += n
            oi.extra[name] = v

    return oi, offset - start


def _deserialize_vartype_element(data: bytes, offset: int) -> tuple[VartypeElement, int]:
    """Deserialize one VartypeListElement."""
    start = offset
    elem = VartypeElement()
    elem.lid, n = s7p.decode_uint32_le(data, offset); offset += n
    elem.symbol_crc, n = s7p.decode_uint32_le(data, offset); offset += n
    bval, n = s7p.decode_byte(data, offset); offset += n
    elem.softdatatype = bval
    elem.attribute_flags, n = s7p.decode_uint16(data, offset); offset += n
    oi_type = (elem.attribute_flags & 0xF000) >> 12
    elem.bitoffsetinfo_flags, n = s7p.decode_byte(data, offset); offset += n
    elem.offset_info, n = _deserialize_offset_info(data, offset, oi_type)
    offset += n
    return elem, offset - start


class PVartypeList:
    """Tag description list (variable type information)."""

    def __init__(self) -> None:
        self.elements: list[VartypeElement] = []
        self.first_id: int = 0

    @classmethod
    def deserialize(cls, data: bytes, offset: int) -> tuple[PVartypeList, int]:
        start = offset
        vt = cls()
        block_len, n = s7p.decode_uint16(data, offset); offset += n
        max_offset = offset + block_len
        vt.first_id, n = s7p.decode_uint32_le(data, offset); offset += n

        while block_len > 0:
            while offset < max_offset:
                elem, n = _deserialize_vartype_element(data, offset)
                offset += n
                vt.elements.append(elem)
            block_len, n = s7p.decode_uint16(data, offset); offset += n
            max_offset = offset + block_len
        return vt, offset - start


# ===========================================================================
# PVarnameList — variable name list
# ===========================================================================

class PVarnameList:
    """Variable name list."""

    def __init__(self) -> None:
        self.names: list[str] = []

    @classmethod
    def deserialize(cls, data: bytes, offset: int) -> tuple[PVarnameList, int]:
        start = offset
        vn = cls()
        block_len, n = s7p.decode_uint16(data, offset); offset += n
        max_offset = offset + block_len

        while block_len > 0:
            while offset < max_offset:
                name_len, n = s7p.decode_byte(data, offset); offset += n
                name, n = s7p.decode_wstring(data, offset, name_len); offset += n
                vn.names.append(name)
                _, n = s7p.decode_byte(data, offset); offset += n  # null terminator
            block_len, n = s7p.decode_uint16(data, offset); offset += n
            max_offset = offset + block_len
        return vn, offset - start


# ===========================================================================
# ItemAddress — used in Get/SetMultiVariables requests
# ===========================================================================

class ItemAddress:
    """Address descriptor for variable access."""

    def __init__(self, area: int = 0, sub_area: int = Ids.DB_VALUE_ACTUAL) -> None:
        self.symbol_crc: int = 0
        self.access_area: int = area
        self.access_sub_area: int = sub_area
        self.lid: list[int] = []

    @classmethod
    def from_access_string(cls, access_string: str) -> ItemAddress:
        """Parse hex-dot access string like ``8A0E0001.A``."""
        parts = access_string.split(".")
        ids = [int(p, 16) for p in parts]
        addr = cls()
        addr.symbol_crc = 0
        addr.access_area = ids[0]
        if addr.access_area >= 0x8A0E0000:
            addr.access_sub_area = Ids.DB_VALUE_ACTUAL
        elif addr.access_area in (
            Ids.NATIVE_OBJECTS_THE_S7_TIMERS_RID,
            Ids.NATIVE_OBJECTS_THE_S7_COUNTERS_RID,
            Ids.NATIVE_OBJECTS_THE_I_AREA_RID,
            Ids.NATIVE_OBJECTS_THE_Q_AREA_RID,
            Ids.NATIVE_OBJECTS_THE_M_AREA_RID,
        ):
            addr.access_sub_area = Ids.CONTROLLER_AREA_VALUE_ACTUAL
        addr.lid = ids[1:]
        return addr

    def get_number_of_fields(self) -> int:
        return 4 + len(self.lid)

    def set_datablock(self, number: int) -> None:
        self.access_area = (number & 0xFFFF) + 0x8A0E0000

    def serialize(self, buf: bytearray) -> int:
        ret = 0
        ret += s7p.encode_uint32_vlq(buf, self.symbol_crc)
        ret += s7p.encode_uint32_vlq(buf, self.access_area)
        ret += s7p.encode_uint32_vlq(buf, len(self.lid) + 1)
        ret += s7p.encode_uint32_vlq(buf, self.access_sub_area)
        for lid_val in self.lid:
            ret += s7p.encode_uint32_vlq(buf, lid_val)
        return ret


# ===========================================================================
# Decode/Encode helpers — DecodeObject, DecodeObjectList, EncodeObjectQualifier
#
# In C# these live in S7p.cs, but they depend on PObject and PValue,
# which would create circular imports if placed in s7p.py.
# ===========================================================================

def decode_object(data: bytes, offset: int, as_list: bool = False) -> tuple[PObject | None, int]:
    """Decode a PObject from the wire, including nested children.

    Ported from S7p.DecodeObject in S7p.cs.
    """
    from s7commplus.protocol.values import PValue  # late import

    start = offset
    obj: PObject | None = None
    terminate = False

    while not terminate:
        if offset >= len(data):
            break
        tag_id, n = s7p.decode_byte(data, offset); offset += n

        if tag_id == ElementID.START_OF_OBJECT:
            if obj is None:
                obj = PObject()
                obj.relation_id, n = s7p.decode_uint32(data, offset); offset += n
                obj.class_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
                obj.class_flags, n = s7p.decode_uint32_vlq(data, offset); offset += n
                obj.attribute_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
                if not as_list:
                    _, n = decode_object(data, offset, as_list=False)
                    # The recursive call handles adding child objects
                    # But we need to re-parse to actually populate children
                    # Let's do it properly: recurse into self
                    child_obj, n = _decode_object_inner(data, offset, obj)
                    offset += n
            else:
                new_obj = PObject()
                new_obj.relation_id, n = s7p.decode_uint32(data, offset); offset += n
                new_obj.class_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
                new_obj.class_flags, n = s7p.decode_uint32_vlq(data, offset); offset += n
                new_obj.attribute_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
                _, n = _decode_object_inner(data, offset, new_obj)
                offset += n
                obj.add_object(new_obj)

        elif tag_id == ElementID.TERMINATING_OBJECT:
            terminate = True

        elif tag_id == ElementID.ATTRIBUTE:
            attr_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
            val, n = PValue.deserialize(data, offset); offset += n
            if obj is not None:
                obj.add_attribute(attr_id, val)

        elif tag_id == ElementID.START_OF_TAG_DESCRIPTION:
            pass  # skip, only old 1200 FW2

        elif tag_id == ElementID.VARTYPE_LIST:
            if obj is not None:
                obj.vartype_list, n = PVartypeList.deserialize(data, offset)
                offset += n

        elif tag_id == ElementID.VARNAME_LIST:
            if obj is not None:
                obj.varname_list, n = PVarnameList.deserialize(data, offset)
                offset += n

        else:
            terminate = True

    return obj, offset - start


def _decode_object_inner(data: bytes, offset: int, obj: PObject) -> tuple[PObject, int]:
    """Continue decoding tags into an already-created PObject.

    This handles the recursive case where we've already parsed the header
    (StartOfObject + RID/CLS/FLAGS/AID) and now need to parse contents
    until TerminatingObject.
    """
    from s7commplus.protocol.values import PValue

    start = offset
    terminate = False

    while not terminate:
        if offset >= len(data):
            break
        tag_id, n = s7p.decode_byte(data, offset); offset += n

        if tag_id == ElementID.START_OF_OBJECT:
            new_obj = PObject()
            new_obj.relation_id, n = s7p.decode_uint32(data, offset); offset += n
            new_obj.class_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
            new_obj.class_flags, n = s7p.decode_uint32_vlq(data, offset); offset += n
            new_obj.attribute_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
            _, n = _decode_object_inner(data, offset, new_obj)
            offset += n
            obj.add_object(new_obj)

        elif tag_id == ElementID.TERMINATING_OBJECT:
            terminate = True

        elif tag_id == ElementID.ATTRIBUTE:
            attr_id, n = s7p.decode_uint32_vlq(data, offset); offset += n
            val, n = PValue.deserialize(data, offset); offset += n
            obj.add_attribute(attr_id, val)

        elif tag_id == ElementID.START_OF_TAG_DESCRIPTION:
            pass

        elif tag_id == ElementID.VARTYPE_LIST:
            obj.vartype_list, n = PVartypeList.deserialize(data, offset)
            offset += n

        elif tag_id == ElementID.VARNAME_LIST:
            obj.varname_list, n = PVarnameList.deserialize(data, offset)
            offset += n

        else:
            terminate = True

    return obj, offset - start


def decode_object_list(data: bytes, offset: int) -> tuple[list[PObject], int]:
    """Decode a list of PObjects (each starts with 0xA1)."""
    start = offset
    obj_list: list[PObject] = []

    while offset < len(data):
        tag_id, _ = s7p.decode_byte(data, offset)
        if tag_id != ElementID.START_OF_OBJECT:
            break
        obj, n = decode_object(data, offset, as_list=True)
        offset += n
        if obj is not None:
            obj_list.append(obj)

    return obj_list, offset - start


def encode_object_qualifier(buf: bytearray) -> int:
    """Encode an ObjectQualifier block (ParentRID=0, CompositionAID=0, KeyQualifier=0)."""
    from s7commplus.protocol.values import ValueRID, ValueAID, ValueUDInt

    ret = 0
    ret += s7p.encode_uint32(buf, Ids.OBJECT_QUALIFIER)

    ret += s7p.encode_uint32_vlq(buf, Ids.PARENT_RID)
    ret += ValueRID(0).serialize(buf)

    ret += s7p.encode_uint32_vlq(buf, Ids.COMPOSITION_AID)
    ret += ValueAID(0).serialize(buf)

    ret += s7p.encode_uint32_vlq(buf, Ids.KEY_QUALIFIER)
    ret += ValueUDInt(0).serialize(buf)

    ret += s7p.encode_byte(buf, 0)  # terminator
    return ret
