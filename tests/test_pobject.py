"""
Unit tests for s7commplus.protocol.pobject — PObject, decode/encode, ItemAddress.
"""

import pytest

from s7commplus.protocol import s7p
from s7commplus.protocol.constants import ElementID, Ids, Datatype
from s7commplus.protocol.values import (
    PValue, ValueBool, ValueUDInt, ValueRID, ValueAID, ValueWString,
)
from s7commplus.protocol.pobject import (
    PObject, ItemAddress,
    decode_object, decode_object_list, encode_object_qualifier,
    PVarnameList, PVartypeList,
)


# ===========================================================================
# PObject serialization
# ===========================================================================

class TestPObjectSerialize:

    def test_empty_object(self):
        obj = PObject(rid=100, cls_id=200, aid=300)
        buf = bytearray()
        n = obj.serialize(buf)
        assert n == len(buf)
        # Should start with START_OF_OBJECT and end with TERMINATING_OBJECT
        assert buf[0] == ElementID.START_OF_OBJECT
        assert buf[-1] == ElementID.TERMINATING_OBJECT

    def test_object_with_attribute(self):
        obj = PObject(rid=1, cls_id=2, aid=0)
        obj.add_attribute(42, ValueBool(True))
        buf = bytearray()
        obj.serialize(buf)
        # Should contain ATTRIBUTE tag
        assert ElementID.ATTRIBUTE in buf

    def test_object_with_child(self):
        parent = PObject(rid=1, cls_id=2, aid=0)
        child = PObject(rid=10, cls_id=20, aid=0)
        child.add_attribute(1, ValueUDInt(99))
        parent.add_object(child)
        buf = bytearray()
        parent.serialize(buf)
        # Two START_OF_OBJECT tags (parent + child)
        count = sum(1 for b in buf if b == ElementID.START_OF_OBJECT)
        assert count == 2

    def test_object_with_relation(self):
        obj = PObject(rid=1, cls_id=2, aid=0)
        obj.add_relation(100, 0xDEAD)
        buf = bytearray()
        obj.serialize(buf)
        assert ElementID.RELATION in buf


# ===========================================================================
# PObject decode round-trip
# ===========================================================================

class TestDecodeObject:

    def test_roundtrip_empty(self):
        """Serialize then decode an empty PObject."""
        obj = PObject(rid=100, cls_id=200, aid=300)
        buf = bytearray()
        obj.serialize(buf)
        decoded, consumed = decode_object(bytes(buf), 0)
        assert consumed == len(buf)
        assert decoded is not None
        assert decoded.relation_id == 100
        assert decoded.class_id == 200
        assert decoded.attribute_id == 300

    def test_roundtrip_with_attributes(self):
        obj = PObject(rid=1, cls_id=2, aid=0)
        obj.add_attribute(Ids.SERVER_SESSION_CLIENT_RID, ValueRID(0x80C3C901))
        obj.add_attribute(42, ValueBool(True))
        buf = bytearray()
        obj.serialize(buf)
        decoded, consumed = decode_object(bytes(buf), 0)
        assert consumed == len(buf)
        rid_val = decoded.get_attribute(Ids.SERVER_SESSION_CLIENT_RID)
        assert rid_val is not None
        assert rid_val.value == 0x80C3C901
        bool_val = decoded.get_attribute(42)
        assert bool_val.value is True

    def test_roundtrip_nested_objects(self):
        parent = PObject(rid=1, cls_id=2, aid=0)
        child = PObject(rid=10, cls_id=20, aid=0)
        child.add_attribute(1, ValueUDInt(99))
        parent.add_object(child)
        buf = bytearray()
        parent.serialize(buf)
        decoded, consumed = decode_object(bytes(buf), 0)
        assert consumed == len(buf)
        children = decoded.get_all_objects()
        assert len(children) == 1
        assert children[0].relation_id == 10
        assert children[0].class_id == 20
        assert children[0].get_attribute(1).value == 99

    def test_decode_object_at_offset(self):
        """Decode should work with a nonzero offset."""
        prefix = b"\xFF\xFF"
        obj = PObject(rid=5, cls_id=6, aid=7)
        buf = bytearray()
        obj.serialize(buf)
        data = prefix + bytes(buf)
        decoded, consumed = decode_object(data, 2)
        assert decoded.relation_id == 5

    def test_decode_null_server_session(self):
        """Test the Null Server Session object from CreateObjectRequest."""
        obj = PObject(rid=Ids.GET_NEW_RID_ON_SERVER, cls_id=Ids.CLASS_SERVER_SESSION, aid=Ids.NONE)
        obj.add_attribute(Ids.SERVER_SESSION_CLIENT_RID, ValueRID(0x80C3C901))
        sub = PObject(rid=Ids.GET_NEW_RID_ON_SERVER, cls_id=Ids.CLASS_SUBSCRIPTIONS, aid=Ids.NONE)
        obj.add_object(sub)
        buf = bytearray()
        obj.serialize(buf)
        decoded, consumed = decode_object(bytes(buf), 0)
        assert consumed == len(buf)
        assert decoded.class_id == Ids.CLASS_SERVER_SESSION
        assert decoded.get_attribute(Ids.SERVER_SESSION_CLIENT_RID).value == 0x80C3C901
        subs = decoded.get_objects_by_class(Ids.CLASS_SUBSCRIPTIONS)
        assert len(subs) == 1


# ===========================================================================
# DecodeObjectList
# ===========================================================================

class TestDecodeObjectList:

    def test_empty_list(self):
        """Non-StartOfObject byte → empty list."""
        data = bytes([0x00])
        obj_list, consumed = decode_object_list(data, 0)
        assert len(obj_list) == 0
        assert consumed == 0

    def test_single_object(self):
        obj = PObject(rid=1, cls_id=2, aid=3)
        obj.add_attribute(10, ValueBool(True))
        buf = bytearray()
        obj.serialize(buf)
        # Add a trailing non-StartOfObject byte
        buf.append(0x00)
        obj_list, consumed = decode_object_list(bytes(buf), 0)
        assert len(obj_list) == 1
        assert obj_list[0].relation_id == 1

    def test_multiple_objects(self):
        buf = bytearray()
        for i in range(3):
            obj = PObject(rid=i, cls_id=i + 10, aid=0)
            obj.serialize(buf)
        buf.append(0x00)  # terminator
        obj_list, consumed = decode_object_list(bytes(buf), 0)
        assert len(obj_list) == 3
        assert [o.relation_id for o in obj_list] == [0, 1, 2]


# ===========================================================================
# EncodeObjectQualifier
# ===========================================================================

class TestEncodeObjectQualifier:

    def test_encode(self):
        buf = bytearray()
        n = encode_object_qualifier(buf)
        assert n == len(buf)
        # Should start with ObjectQualifier constant (1256 as uint32)
        oq, _ = s7p.decode_uint32(bytes(buf), 0)
        assert oq == Ids.OBJECT_QUALIFIER
        # Should end with 0x00 terminator
        assert buf[-1] == 0x00

    def test_contains_parent_rid(self):
        """The encoded qualifier should contain ParentRID, CompositionAID, KeyQualifier."""
        buf = bytearray()
        encode_object_qualifier(buf)
        data = bytes(buf)
        # After the uint32 ObjectQualifier, first VLQ should be ParentRID id
        offset = 4
        parent_rid_id, n = s7p.decode_uint32_vlq(data, offset)
        assert parent_rid_id == Ids.PARENT_RID


# ===========================================================================
# ItemAddress
# ===========================================================================

class TestItemAddress:

    def test_default(self):
        addr = ItemAddress()
        assert addr.symbol_crc == 0
        assert addr.access_area == 0
        assert addr.access_sub_area == Ids.DB_VALUE_ACTUAL
        assert addr.lid == []

    def test_from_access_string(self):
        addr = ItemAddress.from_access_string("8A0E0001.A")
        assert addr.access_area == 0x8A0E0001
        assert addr.access_sub_area == Ids.DB_VALUE_ACTUAL
        assert addr.lid == [0x0A]

    def test_set_datablock(self):
        addr = ItemAddress()
        addr.set_datablock(1)
        assert addr.access_area == 0x8A0E0001

    def test_number_of_fields(self):
        addr = ItemAddress()
        assert addr.get_number_of_fields() == 4
        addr.lid = [1, 2, 3]
        assert addr.get_number_of_fields() == 7

    def test_serialize_roundtrip(self):
        addr = ItemAddress(area=0x8A0E0001, sub_area=Ids.DB_VALUE_ACTUAL)
        addr.lid = [0x0A]
        buf = bytearray()
        n = addr.serialize(buf)
        assert n == len(buf)
        assert len(buf) > 0

    def test_controller_area_access(self):
        addr = ItemAddress.from_access_string("50.A")
        # 0x50 = 80 = NATIVE_OBJECTS_THE_I_AREA_RID
        assert addr.access_area == 0x50
        assert addr.access_sub_area == Ids.CONTROLLER_AREA_VALUE_ACTUAL
