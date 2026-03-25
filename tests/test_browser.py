"""Tests for Phase D — Browser, VarInfo, VartypeElement helpers, OffsetInfo enhancements."""

from __future__ import annotations

import pytest

from s7commplus.protocol.constants import Softdatatype, Ids
from s7commplus.protocol.pobject import (
    OffsetInfo, VartypeElement, PObject, PVartypeList, PVarnameList,
    _deserialize_offset_info,
)
from s7commplus.protocol import s7p
from s7commplus.protocol.values import ValueUDInt
from s7commplus.client_api.var_info import Node, NodeType, VarInfo
from s7commplus.client_api.browser import (
    Browser, _get_size_of_datatype, _is_softdatatype_supported,
)


# ===================================================================
# OffsetInfo method tests
# ===================================================================

class TestOffsetInfoMethods:
    def test_has_relation_true(self):
        for t in (0, 5, 6, 7, 12, 13, 14, 15):
            oi = OffsetInfo()
            oi.offset_type = t
            assert oi.has_relation(), f"type {t} should have relation"

    def test_has_relation_false(self):
        for t in (1, 2, 3, 4, 8, 9, 10, 11):
            oi = OffsetInfo()
            oi.offset_type = t
            assert not oi.has_relation(), f"type {t} should not have relation"

    def test_is_1dim(self):
        for t in (3, 6, 10, 13):
            oi = OffsetInfo()
            oi.offset_type = t
            assert oi.is_1dim()
        for t in (0, 1, 2, 4, 5, 7, 8, 9, 11, 12, 14, 15):
            oi = OffsetInfo()
            oi.offset_type = t
            assert not oi.is_1dim()

    def test_is_mdim(self):
        for t in (4, 7, 11, 14):
            oi = OffsetInfo()
            oi.offset_type = t
            assert oi.is_mdim()
        for t in (0, 1, 2, 3, 5, 6, 8, 9, 10, 12, 13, 15):
            oi = OffsetInfo()
            oi.offset_type = t
            assert not oi.is_mdim()

    def test_constants(self):
        assert OffsetInfo.FB_ARRAY == 0
        assert OffsetInfo.STD == 8
        assert OffsetInfo.STRING == 9
        assert OffsetInfo.ARRAY_1DIM == 10
        assert OffsetInfo.ARRAY_MDIM == 11
        assert OffsetInfo.STRUCT == 12
        assert OffsetInfo.STRUCT_1DIM == 13
        assert OffsetInfo.STRUCT_MDIM == 14
        assert OffsetInfo.FB_SFB == 15


# ===================================================================
# VartypeElement helper tests
# ===================================================================

class TestVartypeElementHelpers:
    def test_get_attribute_bitoffset(self):
        vte = VartypeElement()
        vte.attribute_flags = 0x0005  # bits 0-2 = 5
        assert vte.get_attribute_bitoffset() == 5

    def test_get_attribute_bitoffset_masked(self):
        vte = VartypeElement()
        vte.attribute_flags = 0xFFF7  # bits 0-2 = 7
        assert vte.get_attribute_bitoffset() == 7

    def test_get_attribute_section(self):
        vte = VartypeElement()
        vte.attribute_flags = 0x0030  # bits 4-6 = 3
        assert vte.get_attribute_section() == 3

    def test_get_attribute_section_isolated(self):
        vte = VartypeElement()
        vte.attribute_flags = 0xFF8F  # bits 4-6 = 0
        assert vte.get_attribute_section() == 0

    def test_get_bitoffsetinfo_flag_classic_true(self):
        vte = VartypeElement()
        vte.bitoffsetinfo_flags = 0x08
        assert vte.get_bitoffsetinfo_flag_classic() is True

    def test_get_bitoffsetinfo_flag_classic_false(self):
        vte = VartypeElement()
        vte.bitoffsetinfo_flags = 0xF7
        assert vte.get_bitoffsetinfo_flag_classic() is False

    def test_get_bitoffsetinfo_nonoptimized_bitoffset(self):
        vte = VartypeElement()
        vte.bitoffsetinfo_flags = 0x50  # bits 4-6 = 5
        assert vte.get_bitoffsetinfo_nonoptimized_bitoffset() == 5

    def test_get_bitoffsetinfo_optimized_bitoffset(self):
        vte = VartypeElement()
        vte.bitoffsetinfo_flags = 0x03  # bits 0-2 = 3
        assert vte.get_bitoffsetinfo_optimized_bitoffset() == 3

    def test_combined_flags(self):
        vte = VartypeElement()
        vte.bitoffsetinfo_flags = 0xFD  # retain=1, nonopt=7, classic=1, opt=5
        assert vte.get_bitoffsetinfo_optimized_bitoffset() == 5
        assert vte.get_bitoffsetinfo_flag_classic() is True
        assert vte.get_bitoffsetinfo_nonoptimized_bitoffset() == 7

    def test_constants_exist(self):
        assert VartypeElement.ATTR_OFFSETINFOTYPE == 0xF000
        assert VartypeElement.ATTR_BITOFFSET == 0x0007
        assert VartypeElement.BITINFO_RETAIN == 0x80
        assert VartypeElement.BITINFO_CLASSIC == 0x08


# ===================================================================
# Offset info deserialization — unspecified_offsetinfo1 storage
# ===================================================================

class TestOffsetInfoUnspecifiedStorage:
    def _build_array1dim_data(self, v1=10, v2=20):
        """Build raw bytes for Array1Dim offset info type (3 or 10)."""
        buf = bytearray()
        buf += v1.to_bytes(2, "little")    # unspecified_offsetinfo1
        buf += v2.to_bytes(2, "little")    # unspecified_offsetinfo2
        buf += (100).to_bytes(4, "little")  # optimized_address
        buf += (200).to_bytes(4, "little")  # nonoptimized_address
        buf += (0).to_bytes(4, "little", signed=True)  # array_lower_bounds
        buf += (5).to_bytes(4, "little")    # array_element_count
        return bytes(buf)

    def test_array1dim_stores_unspecified(self):
        data = self._build_array1dim_data(v1=42)
        oi, consumed = _deserialize_offset_info(data, 0, 10)
        assert oi.extra["unspecified_offsetinfo1"] == 42
        assert oi.optimized_address == 100
        assert oi.array_element_count == 5

    def test_struct_elem_array1dim_stores_unspecified(self):
        data = self._build_array1dim_data(v1=7)
        oi, consumed = _deserialize_offset_info(data, 0, 3)
        assert oi.extra["unspecified_offsetinfo1"] == 7

    def _build_arraymdim_data(self, v1=15):
        """Build raw bytes for ArrayMDim offset info type (4 or 11)."""
        buf = bytearray()
        buf += v1.to_bytes(2, "little")     # unspecified_offsetinfo1
        buf += (0).to_bytes(2, "little")    # unspecified_offsetinfo2
        buf += (100).to_bytes(4, "little")  # optimized_address
        buf += (200).to_bytes(4, "little")  # nonoptimized_address
        buf += (0).to_bytes(4, "little", signed=True)  # array_lower_bounds
        buf += (6).to_bytes(4, "little")    # array_element_count
        for _ in range(6):
            buf += (0).to_bytes(4, "little", signed=True)
        for _ in range(6):
            buf += (0).to_bytes(4, "little")
        return bytes(buf)

    def test_arraymdim_stores_unspecified(self):
        data = self._build_arraymdim_data(v1=254)
        oi, consumed = _deserialize_offset_info(data, 0, 11)
        assert oi.extra["unspecified_offsetinfo1"] == 254

    def test_struct_elem_arraymdim_stores_unspecified(self):
        data = self._build_arraymdim_data(v1=128)
        oi, consumed = _deserialize_offset_info(data, 0, 4)
        assert oi.extra["unspecified_offsetinfo1"] == 128


# ===================================================================
# VarInfo / Node / NodeType tests
# ===================================================================

class TestVarInfoNode:
    def test_node_defaults(self):
        n = Node()
        assert n.node_type == NodeType.UNDEFINED
        assert n.name == ""
        assert n.access_id == 0
        assert n.children == []

    def test_varinfo_repr(self):
        v = VarInfo()
        v.name = "DB1.x"
        v.access_sequence = "8A0E0001.A"
        v.softdatatype = 1
        r = repr(v)
        assert "DB1.x" in r
        assert "8A0E0001.A" in r

    def test_node_type_values(self):
        assert NodeType.UNDEFINED == 0
        assert NodeType.ROOT == 1
        assert NodeType.ARRAY == 3
        assert NodeType.STRUCT_ARRAY == 4


# ===================================================================
# Datatype size and supported datatype tests
# ===================================================================

class TestDatatypeSizeAndSupport:
    def test_basic_sizes(self):
        vte = VartypeElement()
        vte.softdatatype = Softdatatype.BOOL
        assert _get_size_of_datatype(vte) == 1
        vte.softdatatype = Softdatatype.INT
        assert _get_size_of_datatype(vte) == 2
        vte.softdatatype = Softdatatype.DINT
        assert _get_size_of_datatype(vte) == 4
        vte.softdatatype = Softdatatype.LREAL
        assert _get_size_of_datatype(vte) == 8

    def test_string_size_from_offset_info(self):
        vte = VartypeElement()
        vte.softdatatype = Softdatatype.STRING
        oi = OffsetInfo()
        oi.extra["unspecified_offsetinfo1"] = 254
        vte.offset_info = oi
        assert _get_size_of_datatype(vte) == 256  # 254 + 2

    def test_wstring_size_from_offset_info(self):
        vte = VartypeElement()
        vte.softdatatype = Softdatatype.WSTRING
        oi = OffsetInfo()
        oi.extra["unspecified_offsetinfo1"] = 100
        vte.offset_info = oi
        assert _get_size_of_datatype(vte) == 102

    def test_string_no_offset_info(self):
        vte = VartypeElement()
        vte.softdatatype = Softdatatype.STRING
        vte.offset_info = None
        assert _get_size_of_datatype(vte) == 2

    def test_unknown_datatype_returns_zero(self):
        vte = VartypeElement()
        vte.softdatatype = 255
        assert _get_size_of_datatype(vte) == 0

    def test_supported_datatypes(self):
        assert _is_softdatatype_supported(Softdatatype.BOOL)
        assert _is_softdatatype_supported(Softdatatype.STRING)
        assert _is_softdatatype_supported(Softdatatype.WSTRING)
        assert _is_softdatatype_supported(Softdatatype.LREAL)
        assert _is_softdatatype_supported(Softdatatype.DB_DYN)

    def test_unsupported_datatype(self):
        assert not _is_softdatatype_supported(255)
        assert not _is_softdatatype_supported(Softdatatype.VOID)


# ===================================================================
# Browser — helper to build test fixtures
# ===================================================================

def _make_vte(lid, name_unused="", sdt=Softdatatype.INT, oi_type=8,
              opt_addr=0, nonopt_addr=0, attr_flags=0, bitinfo=0):
    """Create a VartypeElement with an OffsetInfo."""
    vte = VartypeElement()
    vte.lid = lid
    vte.softdatatype = sdt
    vte.attribute_flags = attr_flags | ((oi_type & 0xF) << 12)
    vte.bitoffsetinfo_flags = bitinfo
    oi = OffsetInfo()
    oi.offset_type = oi_type
    oi.optimized_address = opt_addr
    oi.nonoptimized_address = nonopt_addr
    vte.offset_info = oi
    return vte


def _make_vte_1dim(lid, sdt, count, lower=0, has_rel=False, rel_id=0,
                   opt_addr=0, nonopt_addr=0, unspec1=0):
    """Create a VartypeElement with Array1Dim offset info."""
    oi_type = 13 if has_rel else 10  # Struct1Dim vs Array1Dim
    vte = VartypeElement()
    vte.lid = lid
    vte.softdatatype = sdt
    vte.attribute_flags = (oi_type & 0xF) << 12
    vte.bitoffsetinfo_flags = 0
    oi = OffsetInfo()
    oi.offset_type = oi_type
    oi.optimized_address = opt_addr
    oi.nonoptimized_address = nonopt_addr
    oi.array_lower_bounds = lower
    oi.array_element_count = count
    if has_rel:
        oi.relation_id = rel_id
    if unspec1:
        oi.extra["unspecified_offsetinfo1"] = unspec1
    vte.offset_info = oi
    return vte


def _make_vte_mdim(lid, sdt, total_count, lower, mdim_counts, mdim_lowers,
                   has_rel=False, rel_id=0, opt_addr=0, nonopt_addr=0):
    """Create a VartypeElement with ArrayMDim offset info."""
    oi_type = 14 if has_rel else 11
    vte = VartypeElement()
    vte.lid = lid
    vte.softdatatype = sdt
    vte.attribute_flags = (oi_type & 0xF) << 12
    vte.bitoffsetinfo_flags = 0
    oi = OffsetInfo()
    oi.offset_type = oi_type
    oi.optimized_address = opt_addr
    oi.nonoptimized_address = nonopt_addr
    oi.array_lower_bounds = lower
    oi.array_element_count = total_count
    oi.mdim_element_counts = list(mdim_counts) + [0] * (6 - len(mdim_counts))
    oi.mdim_lower_bounds = list(mdim_lowers) + [0] * (6 - len(mdim_lowers))
    if has_rel:
        oi.relation_id = rel_id
    vte.offset_info = oi
    return vte


def _make_vte_struct(lid, sdt, rel_id, opt_addr=0, nonopt_addr=0):
    """Create a VartypeElement with Struct offset info (has relation, not array)."""
    oi_type = 12  # STRUCT
    vte = VartypeElement()
    vte.lid = lid
    vte.softdatatype = sdt
    vte.attribute_flags = (oi_type & 0xF) << 12
    vte.bitoffsetinfo_flags = 0
    oi = OffsetInfo()
    oi.offset_type = oi_type
    oi.optimized_address = opt_addr
    oi.nonoptimized_address = nonopt_addr
    oi.relation_id = rel_id
    vte.offset_info = oi
    return vte


def _make_pobject(rel_id, vte_list, name_list, cls_id=0, tcom_size=None):
    """Create a PObject with VartypeList and VarnameList for testing."""
    obj = PObject(rid=rel_id, cls_id=cls_id)
    vtl = PVartypeList()
    vtl.elements = vte_list
    obj.vartype_list = vtl
    vnl = PVarnameList()
    vnl.names = name_list
    obj.varname_list = vnl
    if tcom_size is not None:
        obj.add_attribute(Ids.TI_TCOM_SIZE, ValueUDInt(tcom_size))
    return obj


# ===================================================================
# Browser — simple scalar DB
# ===================================================================

class TestBrowserSimpleDB:
    """A DB with a few scalar variables: INT, BOOL, REAL."""

    def setup_method(self):
        self.browser = Browser()

        # Type info object for DB1's type
        vte_int = _make_vte(0xA, sdt=Softdatatype.INT, opt_addr=0, nonopt_addr=0)
        vte_bool = _make_vte(0xB, sdt=Softdatatype.BOOL, opt_addr=2, nonopt_addr=2,
                             attr_flags=0x0003, bitinfo=0x38)  # bitoffset=3, classic, nonopt=3
        vte_real = _make_vte(0xC, sdt=Softdatatype.REAL, opt_addr=4, nonopt_addr=4)

        type_obj = _make_pobject(
            rel_id=1000,
            vte_list=[vte_int, vte_bool, vte_real],
            name_list=["MyInt", "MyBool", "MyReal"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB1", 0x8A0E0001, 1000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_var_count(self):
        assert len(self.browser.var_info_list) == 3

    def test_int_var(self):
        v = self.browser.var_info_list[0]
        assert v.name == "DB1.MyInt"
        assert v.access_sequence == "8A0E0001.A"
        assert v.softdatatype == Softdatatype.INT
        assert v.opt_address == 0
        assert v.nonopt_address == 0

    def test_bool_var_bitoffsets(self):
        v = self.browser.var_info_list[1]
        assert v.name == "DB1.MyBool"
        assert v.softdatatype == Softdatatype.BOOL
        assert v.opt_bitoffset == 3  # from attribute_flags & 0x7
        # classic flag is set (0x08), so nonopt comes from bitoffsetinfo bits 4-6
        assert v.nonopt_bitoffset == 3  # (0x38 & 0x70) >> 4 = 3

    def test_real_var(self):
        v = self.browser.var_info_list[2]
        assert v.name == "DB1.MyReal"
        assert v.access_sequence == "8A0E0001.C"
        assert v.opt_address == 4
        assert v.nonopt_address == 4


# ===================================================================
# Browser — 1D flat array
# ===================================================================

class TestBrowser1DimArray:
    """A DB with Array[0..2] of INT."""

    def setup_method(self):
        self.browser = Browser()

        vte_arr = _make_vte_1dim(
            lid=0x10, sdt=Softdatatype.INT, count=3, lower=0,
            opt_addr=0, nonopt_addr=0,
        )

        type_obj = _make_pobject(
            rel_id=2000,
            vte_list=[vte_arr],
            name_list=["MyArray"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB2", 0x8A0E0002, 2000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_element_count(self):
        assert len(self.browser.var_info_list) == 3

    def test_element_names(self):
        names = [v.name for v in self.browser.var_info_list]
        assert names == ["DB2.MyArray[0]", "DB2.MyArray[1]", "DB2.MyArray[2]"]

    def test_element_access_sequences(self):
        seqs = [v.access_sequence for v in self.browser.var_info_list]
        # Array elements: parent LID then .{index_hex}
        assert seqs == [
            "8A0E0002.10.0",
            "8A0E0002.10.1",
            "8A0E0002.10.2",
        ]

    def test_element_offsets(self):
        # INT = 2 bytes each
        for i, v in enumerate(self.browser.var_info_list):
            assert v.opt_address == i * 2
            assert v.nonopt_address == i * 2


# ===================================================================
# Browser — 1D array with nonzero lower bound
# ===================================================================

class TestBrowser1DimArrayWithLowerBound:
    """Array[5..7] of DINT."""

    def setup_method(self):
        self.browser = Browser()

        vte_arr = _make_vte_1dim(
            lid=0x20, sdt=Softdatatype.DINT, count=3, lower=5,
            opt_addr=0, nonopt_addr=0,
        )

        type_obj = _make_pobject(
            rel_id=3000,
            vte_list=[vte_arr],
            name_list=["Arr"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB3", 0x8A0E0003, 3000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_names_include_lower_bound(self):
        names = [v.name for v in self.browser.var_info_list]
        assert names == ["DB3.Arr[5]", "DB3.Arr[6]", "DB3.Arr[7]"]

    def test_offsets_are_sequential(self):
        # DINT = 4 bytes, access_id still starts at 0
        for i, v in enumerate(self.browser.var_info_list):
            assert v.opt_address == i * 4


# ===================================================================
# Browser — struct (UDT) without array
# ===================================================================

class TestBrowserStruct:
    """DB with a struct containing INT and REAL members."""

    def setup_method(self):
        self.browser = Browser()

        # Inner struct type info
        vte_inner_int = _make_vte(0x30, sdt=Softdatatype.INT, opt_addr=0, nonopt_addr=0)
        vte_inner_real = _make_vte(0x31, sdt=Softdatatype.REAL, opt_addr=2, nonopt_addr=2)
        inner_obj = _make_pobject(
            rel_id=4001,
            vte_list=[vte_inner_int, vte_inner_real],
            name_list=["field_a", "field_b"],
        )

        # DB-level: one struct member pointing to inner type
        vte_struct = _make_vte_struct(0x40, sdt=Softdatatype.STRUCT, rel_id=4001,
                                      opt_addr=0, nonopt_addr=0)
        db_obj = _make_pobject(
            rel_id=4000,
            vte_list=[vte_struct],
            name_list=["MyStruct"],
        )

        self.browser.set_type_info_objects([db_obj, inner_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB4", 0x8A0E0004, 4000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_var_count(self):
        assert len(self.browser.var_info_list) == 2

    def test_nested_names(self):
        names = [v.name for v in self.browser.var_info_list]
        assert names == ["DB4.MyStruct.field_a", "DB4.MyStruct.field_b"]

    def test_nested_access_sequences(self):
        seqs = [v.access_sequence for v in self.browser.var_info_list]
        assert seqs == ["8A0E0004.40.30", "8A0E0004.40.31"]

    def test_nested_offsets(self):
        assert self.browser.var_info_list[0].opt_address == 0
        assert self.browser.var_info_list[1].opt_address == 2


# ===================================================================
# Browser — 1D struct array (Array[0..1] of UDT)
# ===================================================================

class TestBrowserStructArray:
    """DB with Array[0..1] of a struct (UDT with INT, BYTE)."""

    def setup_method(self):
        self.browser = Browser()

        # Inner struct type
        vte_inner_int = _make_vte(0x50, sdt=Softdatatype.INT, opt_addr=0, nonopt_addr=0)
        vte_inner_byte = _make_vte(0x51, sdt=Softdatatype.BYTE, opt_addr=2, nonopt_addr=2)
        inner_obj = _make_pobject(
            rel_id=5001,
            vte_list=[vte_inner_int, vte_inner_byte],
            name_list=["x", "y"],
            tcom_size=4,  # struct is 4 bytes
        )

        # DB-level: 1Dim struct array pointing to inner type
        vte_arr = _make_vte_1dim(
            lid=0x60, sdt=Softdatatype.STRUCT, count=2, lower=0,
            has_rel=True, rel_id=5001,
            opt_addr=0, nonopt_addr=0,
        )
        db_obj = _make_pobject(
            rel_id=5000,
            vte_list=[vte_arr],
            name_list=["ArrOfUDT"],
        )

        self.browser.set_type_info_objects([db_obj, inner_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB5", 0x8A0E0005, 5000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_var_count(self):
        # 2 array elements × 2 struct members = 4
        assert len(self.browser.var_info_list) == 4

    def test_names(self):
        names = [v.name for v in self.browser.var_info_list]
        assert names == [
            "DB5.ArrOfUDT[0].x",
            "DB5.ArrOfUDT[0].y",
            "DB5.ArrOfUDT[1].x",
            "DB5.ArrOfUDT[1].y",
        ]

    def test_access_sequences_have_dot_1(self):
        """Struct arrays have an additional '.1' between index and access LID."""
        seqs = [v.access_sequence for v in self.browser.var_info_list]
        assert seqs == [
            "8A0E0005.60.0.1.50",
            "8A0E0005.60.0.1.51",
            "8A0E0005.60.1.1.50",
            "8A0E0005.60.1.1.51",
        ]

    def test_offsets(self):
        # Element [0]: offset 0, [1]: offset 4 (tcom_size=4)
        assert self.browser.var_info_list[0].opt_address == 0    # [0].x: base=0, field=0
        assert self.browser.var_info_list[1].opt_address == 2    # [0].y: base=0, field=2
        assert self.browser.var_info_list[2].opt_address == 4    # [1].x: base=4, field=0
        assert self.browser.var_info_list[3].opt_address == 6    # [1].y: base=4, field=2


# ===================================================================
# Browser — MDim flat array
# ===================================================================

class TestBrowserMDimArray:
    """DB with Array[0..1, 0..2] of BYTE (2D, 2×3 = 6 elements)."""

    def setup_method(self):
        self.browser = Browser()

        vte_arr = _make_vte_mdim(
            lid=0x70, sdt=Softdatatype.BYTE,
            total_count=6, lower=0,
            mdim_counts=[3, 2], mdim_lowers=[0, 0],
            opt_addr=0, nonopt_addr=0,
        )

        type_obj = _make_pobject(
            rel_id=6000,
            vte_list=[vte_arr],
            name_list=["Grid"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB6", 0x8A0E0006, 6000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_element_count(self):
        assert len(self.browser.var_info_list) == 6

    def test_element_names(self):
        names = [v.name for v in self.browser.var_info_list]
        # C# iterates dimensions high-to-low in display, lowest varies fastest
        assert names == [
            "DB6.Grid[0,0]",
            "DB6.Grid[0,1]",
            "DB6.Grid[0,2]",
            "DB6.Grid[1,0]",
            "DB6.Grid[1,1]",
            "DB6.Grid[1,2]",
        ]

    def test_offsets(self):
        # BYTE = 1 byte each
        for i, v in enumerate(self.browser.var_info_list):
            assert v.opt_address == i


# ===================================================================
# Browser — BBOOL MDim array padding
# ===================================================================

class TestBrowserBBoolMDimPadding:
    """BBOOL array where lowest dimension count is not a multiple of 8.

    Array[0..1, 0..2] of BBOOL — 3 elements in dim0, padded to next multiple of 8.
    Total 6 elements, but access_id jumps by 8 per row.
    """

    def setup_method(self):
        self.browser = Browser()

        vte_arr = _make_vte_mdim(
            lid=0x80, sdt=Softdatatype.BBOOL,
            total_count=6, lower=0,
            mdim_counts=[3, 2], mdim_lowers=[0, 0],
            opt_addr=0, nonopt_addr=0,
        )

        type_obj = _make_pobject(
            rel_id=7000,
            vte_list=[vte_arr],
            name_list=["Flags"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB7", 0x8A0E0007, 7000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_element_count(self):
        assert len(self.browser.var_info_list) == 6

    def test_access_ids_show_padding(self):
        """After the 3rd element in dim0, access_id jumps to 8 (padded)."""
        seqs = [v.access_sequence for v in self.browser.var_info_list]
        # Row 0: ids 0, 1, 2 then padded → next row starts at id 8
        # Row 1: ids 8, 9, 10
        assert seqs[0].endswith(".0")   # [0,0]
        assert seqs[1].endswith(".1")   # [0,1]
        assert seqs[2].endswith(".2")   # [0,2]
        # After BBOOL padding of 5 (8 - 3%8=5), next id = 2+5+1 = 8
        assert seqs[3].endswith(".8")   # [1,0]
        assert seqs[4].endswith(".9")   # [1,1]
        assert seqs[5].endswith(".A")   # [1,2]


# ===================================================================
# Browser — BOOL bitoffset special cases
# ===================================================================

class TestBrowserBoolBitoffset:
    """BOOL without classic flag — nonopt_bitoffset comes from attribute_flags."""

    def test_bool_no_classic(self):
        browser = Browser()

        # BOOL with classic=0, attribute_bitoffset=5
        vte_bool = _make_vte(
            0xA, sdt=Softdatatype.BOOL, opt_addr=0, nonopt_addr=0,
            attr_flags=0x0005,  # bitoffset = 5
            bitinfo=0x00,       # classic=0
        )

        type_obj = _make_pobject(
            rel_id=8000,
            vte_list=[vte_bool],
            name_list=["flag"],
        )

        browser.set_type_info_objects([type_obj])
        browser.add_block_node(NodeType.ROOT, "DB8", 0x8A0E0008, 8000)
        browser.build_tree()
        browser.build_flat_list()

        v = browser.var_info_list[0]
        assert v.opt_bitoffset == 5
        # Without classic, nonopt also uses attribute bitoffset
        assert v.nonopt_bitoffset == 5

    def test_bbool_bitoffset(self):
        browser = Browser()

        vte_bb = _make_vte(
            0xB, sdt=Softdatatype.BBOOL, opt_addr=0, nonopt_addr=0,
            bitinfo=0x06,  # opt_bitoffset = 6
        )

        type_obj = _make_pobject(
            rel_id=8100,
            vte_list=[vte_bb],
            name_list=["bbflag"],
        )

        browser.set_type_info_objects([type_obj])
        browser.add_block_node(NodeType.ROOT, "DB8b", 0x8A0E0009, 8100)
        browser.build_tree()
        browser.build_flat_list()

        v = browser.var_info_list[0]
        assert v.opt_bitoffset == 6


# ===================================================================
# Browser — String array element size
# ===================================================================

class TestBrowserStringArray:
    """Array[0..1] of String[20] — element size = 20 + 2 = 22."""

    def setup_method(self):
        self.browser = Browser()

        vte_arr = _make_vte_1dim(
            lid=0x90, sdt=Softdatatype.STRING, count=2, lower=0,
            opt_addr=0, nonopt_addr=0,
            unspec1=20,
        )

        type_obj = _make_pobject(
            rel_id=9000,
            vte_list=[vte_arr],
            name_list=["StrArr"],
        )

        self.browser.set_type_info_objects([type_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB9", 0x8A0E000A, 9000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_offsets(self):
        assert len(self.browser.var_info_list) == 2
        assert self.browser.var_info_list[0].opt_address == 0
        assert self.browser.var_info_list[1].opt_address == 22  # 20 + 2


# ===================================================================
# Browser — empty area (no vartype list)
# ===================================================================

class TestBrowserEmptyArea:
    """An area with no variables should produce empty var_info_list."""

    def test_empty_area(self):
        browser = Browser()
        # Object with no vartype_list
        obj = PObject(rid=10000)
        browser.set_type_info_objects([obj])
        browser.add_block_node(NodeType.ROOT, "M", 0x52, 10000)
        browser.build_tree()
        browser.build_flat_list()
        assert len(browser.var_info_list) == 0


# ===================================================================
# Browser — unsupported datatype filtered out
# ===================================================================

class TestBrowserUnsupportedDatatypeFiltered:
    """Variables with unsupported softdatatype don't appear in flat list."""

    def test_unsupported_filtered(self):
        browser = Browser()

        vte_good = _make_vte(0xA, sdt=Softdatatype.INT, opt_addr=0, nonopt_addr=0)
        vte_bad = _make_vte(0xB, sdt=Softdatatype.VOID, opt_addr=2, nonopt_addr=2)

        type_obj = _make_pobject(
            rel_id=11000,
            vte_list=[vte_good, vte_bad],
            name_list=["good", "bad"],
        )

        browser.set_type_info_objects([type_obj])
        browser.add_block_node(NodeType.ROOT, "DB11", 0x8A0E000B, 11000)
        browser.build_tree()
        browser.build_flat_list()

        assert len(browser.var_info_list) == 1
        assert browser.var_info_list[0].name == "DB11.good"


# ===================================================================
# Browser — multiple root nodes (DBs)
# ===================================================================

class TestBrowserMultipleDBs:
    """Two DBs, each with one variable."""

    def test_multiple_dbs(self):
        browser = Browser()

        vte1 = _make_vte(0xA, sdt=Softdatatype.INT, opt_addr=0, nonopt_addr=0)
        obj1 = _make_pobject(rel_id=12001, vte_list=[vte1], name_list=["x"])

        vte2 = _make_vte(0xB, sdt=Softdatatype.REAL, opt_addr=0, nonopt_addr=0)
        obj2 = _make_pobject(rel_id=12002, vte_list=[vte2], name_list=["y"])

        browser.set_type_info_objects([obj1, obj2])
        browser.add_block_node(NodeType.ROOT, "DB10", 0x8A0E000A, 12001)
        browser.add_block_node(NodeType.ROOT, "DB11", 0x8A0E000B, 12002)
        browser.build_tree()
        browser.build_flat_list()

        assert len(browser.var_info_list) == 2
        assert browser.var_info_list[0].name == "DB10.x"
        assert browser.var_info_list[1].name == "DB11.y"


# ===================================================================
# Browser — MDim struct array
# ===================================================================

class TestBrowserMDimStructArray:
    """Array[0..1, 0..1] of UDT (2D struct array, 2×2 = 4 elements)."""

    def setup_method(self):
        self.browser = Browser()

        # Inner struct type
        vte_inner = _make_vte(0xA0, sdt=Softdatatype.BYTE, opt_addr=0, nonopt_addr=0)
        inner_obj = _make_pobject(
            rel_id=13001,
            vte_list=[vte_inner],
            name_list=["val"],
            tcom_size=2,
        )

        # DB-level: MDim struct array
        vte_arr = _make_vte_mdim(
            lid=0xB0, sdt=Softdatatype.STRUCT,
            total_count=4, lower=0,
            mdim_counts=[2, 2], mdim_lowers=[0, 0],
            has_rel=True, rel_id=13001,
            opt_addr=0, nonopt_addr=0,
        )
        db_obj = _make_pobject(
            rel_id=13000,
            vte_list=[vte_arr],
            name_list=["Grid2D"],
        )

        self.browser.set_type_info_objects([db_obj, inner_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB13", 0x8A0E000D, 13000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_var_count(self):
        # 4 array elements × 1 struct member = 4
        assert len(self.browser.var_info_list) == 4

    def test_names(self):
        names = [v.name for v in self.browser.var_info_list]
        assert names == [
            "DB13.Grid2D[0,0].val",
            "DB13.Grid2D[0,1].val",
            "DB13.Grid2D[1,0].val",
            "DB13.Grid2D[1,1].val",
        ]

    def test_struct_array_access_sequences_have_dot_1(self):
        for v in self.browser.var_info_list:
            # Each should contain ".1." for the struct array intermediate
            assert ".1." in v.access_sequence

    def test_offsets(self):
        # tcom_size=2, so offsets: 0, 2, 4, 6 (each struct element is 2 bytes)
        for i, v in enumerate(self.browser.var_info_list):
            assert v.opt_address == i * 2


# ===================================================================
# Browser — nested struct inside struct
# ===================================================================

class TestBrowserNestedStruct:
    """DB with a struct containing another struct."""

    def setup_method(self):
        self.browser = Browser()

        # Inner-inner struct
        vte_leaf = _make_vte(0xD0, sdt=Softdatatype.BYTE, opt_addr=0, nonopt_addr=0)
        inner_inner_obj = _make_pobject(
            rel_id=14002,
            vte_list=[vte_leaf],
            name_list=["leaf"],
        )

        # Inner struct (contains a struct member)
        vte_nested = _make_vte_struct(0xC0, sdt=Softdatatype.STRUCT, rel_id=14002,
                                       opt_addr=0, nonopt_addr=0)
        inner_obj = _make_pobject(
            rel_id=14001,
            vte_list=[vte_nested],
            name_list=["inner"],
        )

        # DB level
        vte_top = _make_vte_struct(0xE0, sdt=Softdatatype.STRUCT, rel_id=14001,
                                    opt_addr=0, nonopt_addr=0)
        db_obj = _make_pobject(
            rel_id=14000,
            vte_list=[vte_top],
            name_list=["outer"],
        )

        self.browser.set_type_info_objects([db_obj, inner_obj, inner_inner_obj])
        self.browser.add_block_node(NodeType.ROOT, "DB14", 0x8A0E000E, 14000)
        self.browser.build_tree()
        self.browser.build_flat_list()

    def test_deeply_nested(self):
        assert len(self.browser.var_info_list) == 1
        v = self.browser.var_info_list[0]
        assert v.name == "DB14.outer.inner.leaf"
        assert v.access_sequence == "8A0E000E.E0.C0.D0"
