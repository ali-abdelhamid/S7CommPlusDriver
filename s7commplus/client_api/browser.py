"""PLC variable browser — builds a tree of tags and flattens to VarInfo list.

Ported from Browser.cs. The Browser receives block nodes (DBs, I/Q/M/C/T areas)
and type-info container objects, then builds a tree of Nodes that is flattened
into a list of VarInfo entries with access sequences and byte/bit offsets.
"""

from __future__ import annotations

from s7commplus.protocol.constants import Ids, Softdatatype
from s7commplus.protocol.pobject import PObject, VartypeElement
from s7commplus.client_api.var_info import Node, NodeType, VarInfo


# ---------------------------------------------------------------------------
# Datatype size map (used for flat array element offset calculation)
# ---------------------------------------------------------------------------

_DATATYPE_SIZE: dict[int, int] = {
    Softdatatype.BOOL: 1,
    Softdatatype.BYTE: 1,
    Softdatatype.CHAR: 1,
    Softdatatype.WORD: 2,
    Softdatatype.INT: 2,
    Softdatatype.DWORD: 4,
    Softdatatype.DINT: 4,
    Softdatatype.REAL: 4,
    Softdatatype.DATE: 2,
    Softdatatype.TIME_OF_DAY: 4,
    Softdatatype.TIME: 4,
    Softdatatype.S5TIME: 2,
    Softdatatype.DATE_AND_TIME: 8,
    Softdatatype.POINTER: 6,
    Softdatatype.ANY: 10,
    Softdatatype.BLOCK_FB: 2,
    Softdatatype.BLOCK_FC: 2,
    Softdatatype.COUNTER: 2,
    Softdatatype.TIMER: 2,
    Softdatatype.BBOOL: 1,
    Softdatatype.LREAL: 8,
    Softdatatype.ULINT: 8,
    Softdatatype.LINT: 8,
    Softdatatype.LWORD: 8,
    Softdatatype.USINT: 1,
    Softdatatype.UINT: 2,
    Softdatatype.UDINT: 4,
    Softdatatype.SINT: 1,
    Softdatatype.WCHAR: 2,
    Softdatatype.LTIME: 8,
    Softdatatype.LTOD: 8,
    Softdatatype.LDT: 8,
    Softdatatype.DTL: 12,
    Softdatatype.REMOTE: 10,
    Softdatatype.AOM_IDENT: 4,
    Softdatatype.EVENT_ANY: 4,
    Softdatatype.EVENT_ATT: 4,
    Softdatatype.AOM_AID: 0,
    Softdatatype.AOM_LINK: 0,
    Softdatatype.EVENT_HWINT: 4,
    Softdatatype.HW_ANY: 2,
    Softdatatype.HW_IOSYSTEM: 2,
    Softdatatype.HW_DPMASTER: 2,
    Softdatatype.HW_DEVICE: 2,
    Softdatatype.HW_DPSLAVE: 2,
    Softdatatype.HW_IO: 2,
    Softdatatype.HW_MODULE: 2,
    Softdatatype.HW_SUBMODULE: 2,
    Softdatatype.HW_HSC: 2,
    Softdatatype.HW_PWM: 2,
    Softdatatype.HW_PTO: 2,
    Softdatatype.HW_INTERFACE: 2,
    Softdatatype.HW_IEPORT: 2,
    Softdatatype.OB_ANY: 2,
    Softdatatype.OB_DELAY: 2,
    Softdatatype.OB_TOD: 2,
    Softdatatype.OB_CYCLIC: 2,
    Softdatatype.OB_ATT: 2,
    Softdatatype.CONN_ANY: 2,
    Softdatatype.CONN_PRG: 2,
    Softdatatype.CONN_OUC: 2,
    Softdatatype.CONN_R_ID: 4,
    Softdatatype.PORT: 2,
    Softdatatype.RTM: 2,
    Softdatatype.PIP: 2,
    Softdatatype.OB_PCYCLE: 2,
    Softdatatype.OB_HWINT: 2,
    Softdatatype.OB_DIAG: 2,
    Softdatatype.OB_TIMEERROR: 2,
    Softdatatype.OB_STARTUP: 2,
    Softdatatype.DB_ANY: 2,
    Softdatatype.DB_WWW: 2,
    Softdatatype.DB_DYN: 2,
}

# All softdatatypes that the browser considers "supported"
_SUPPORTED_SOFTDATATYPES: frozenset[int] = frozenset(_DATATYPE_SIZE.keys()) | {
    Softdatatype.STRING,
    Softdatatype.WSTRING,
}


def _get_size_of_datatype(vte: VartypeElement) -> int:
    """Return byte size for an array element of the given type.

    For STRING/WSTRING the size comes from UnspecifiedOffsetinfo1 + 2.
    """
    sdt = vte.softdatatype
    if sdt in (Softdatatype.STRING, Softdatatype.WSTRING):
        oi = vte.offset_info
        if oi is not None:
            return oi.extra.get("unspecified_offsetinfo1", 0) + 2
        return 2
    return _DATATYPE_SIZE.get(sdt, 0)


def _is_softdatatype_supported(softdatatype: int) -> bool:
    return softdatatype in _SUPPORTED_SOFTDATATYPES


# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------

class Browser:
    """Builds a tree of PLC variables and flattens them into VarInfo entries."""

    def __init__(self) -> None:
        self._root_nodes: list[Node] = []
        self._type_objects: list[PObject] = []
        self._var_info_list: list[VarInfo] = []

    @property
    def var_info_list(self) -> list[VarInfo]:
        return self._var_info_list

    def set_type_info_objects(self, objs: list[PObject]) -> None:
        self._type_objects = objs

    def add_block_node(
        self, node_type: int, name: str, access_id: int, ti_rel_id: int,
    ) -> None:
        node = Node()
        node.node_type = node_type
        node.name = name
        node.access_id = access_id
        node.relation_id = ti_rel_id
        self._root_nodes.append(node)

    # ------------------------------------------------------------------
    # Phase 1: Build tree
    # ------------------------------------------------------------------

    def build_tree(self) -> None:
        for node in self._root_nodes:
            for obj in self._type_objects:
                if obj.relation_id == node.relation_id:
                    self._add_sub_nodes(node, obj)
                    break

    def _add_sub_nodes(self, node: Node, obj: PObject) -> None:
        if obj.vartype_list is None:
            return

        names = obj.varname_list.names if obj.varname_list else []

        for idx, vte in enumerate(obj.vartype_list.elements):
            subnode = Node()
            subnode.name = names[idx] if idx < len(names) else ""
            subnode.softdatatype = vte.softdatatype
            subnode.access_id = vte.lid
            subnode.vte = vte
            node.children.append(subnode)

            oi = vte.offset_info
            if oi is None:
                continue

            if oi.is_1dim():
                self._handle_1dim_array(subnode, vte, oi)
            elif oi.is_mdim():
                self._handle_mdim_array(subnode, vte, oi)
            elif oi.has_relation():
                # Struct / UDT / system library types — not an array
                self._resolve_relation(subnode, oi.relation_id)

    def _handle_1dim_array(self, subnode: Node, vte: VartypeElement, oi) -> None:
        count = oi.array_element_count
        lower = oi.array_lower_bounds

        for i in range(count):
            if oi.has_relation():
                # Struct array — additional ".1" in access path
                arraynode = Node()
                arraynode.node_type = NodeType.STRUCT_ARRAY
                arraynode.name = f"[{i + lower}]"
                arraynode.softdatatype = vte.softdatatype
                arraynode.access_id = i
                arraynode.vte = vte
                subnode.children.append(arraynode)

                for obj in self._type_objects:
                    if obj.relation_id == oi.relation_id:
                        tcom_size = self._get_tcom_size(obj)
                        arraynode.array_adr_offset_opt = i * tcom_size
                        arraynode.array_adr_offset_nonopt = i * tcom_size
                        self._add_sub_nodes(arraynode, obj)
                        break
            else:
                # Flat array of basic datatype
                arraynode = Node()
                arraynode.node_type = NodeType.ARRAY
                arraynode.name = f"[{i + lower}]"
                arraynode.softdatatype = vte.softdatatype
                arraynode.access_id = i
                arraynode.vte = vte

                tcom_size = _get_size_of_datatype(vte)
                arraynode.array_adr_offset_opt = i * tcom_size
                arraynode.array_adr_offset_nonopt = i * tcom_size
                subnode.children.append(arraynode)

    def _handle_mdim_array(self, subnode: Node, vte: VartypeElement, oi) -> None:
        total_count = oi.array_element_count
        lower = oi.array_lower_bounds
        mdim_counts = oi.mdim_element_counts
        mdim_lowers = oi.mdim_lower_bounds

        # Determine actual number of dimensions
        act_dims = sum(1 for c in mdim_counts if c > 0)

        xx = [0] * 6
        n = 1
        access_id = 0

        while n <= total_count:
            # Build name like "[0,1]"
            parts = []
            for j in range(act_dims - 1, -1, -1):
                parts.append(str(xx[j] + mdim_lowers[j]))
            aname = "[" + ",".join(parts) + "]"

            if oi.has_relation():
                arraynode = Node()
                arraynode.node_type = NodeType.STRUCT_ARRAY
                arraynode.name = aname
                arraynode.softdatatype = vte.softdatatype
                arraynode.access_id = access_id
                arraynode.vte = vte
                subnode.children.append(arraynode)

                for obj in self._type_objects:
                    if obj.relation_id == oi.relation_id:
                        tcom_size = self._get_tcom_size(obj)
                        arraynode.array_adr_offset_opt = (n - 1) * tcom_size
                        arraynode.array_adr_offset_nonopt = (n - 1) * tcom_size
                        self._add_sub_nodes(arraynode, obj)
                        break
            else:
                arraynode = Node()
                arraynode.node_type = NodeType.ARRAY
                arraynode.name = aname
                arraynode.softdatatype = vte.softdatatype
                arraynode.access_id = access_id
                arraynode.vte = vte

                tcom_size = _get_size_of_datatype(vte)
                arraynode.array_adr_offset_opt = (n - 1) * tcom_size
                arraynode.array_adr_offset_nonopt = (n - 1) * tcom_size
                subnode.children.append(arraynode)

            # Advance dimension counters
            xx[0] += 1

            # BBOOL: pad lowest dimension to multiple of 8
            if (vte.softdatatype == Softdatatype.BBOOL
                    and xx[0] >= mdim_counts[0]
                    and mdim_counts[0] % 8 != 0):
                access_id += 8 - (xx[0] % 8)

            for dim in range(5):
                if xx[dim] >= mdim_counts[dim]:
                    xx[dim] = 0
                    xx[dim + 1] += 1

            access_id += 1
            n += 1

    def _resolve_relation(self, node: Node, relation_id: int) -> None:
        for obj in self._type_objects:
            if obj.relation_id == relation_id:
                self._add_sub_nodes(node, obj)
                return

    @staticmethod
    def _get_tcom_size(obj: PObject) -> int:
        """Get TComSize attribute from a type-info PObject."""
        attr = obj.get_attribute(Ids.TI_TCOM_SIZE)
        if attr is not None:
            return attr.value
        return 0

    # ------------------------------------------------------------------
    # Phase 2: Build flat list
    # ------------------------------------------------------------------

    def build_flat_list(self) -> None:
        self._var_info_list = []
        for node in self._root_nodes:
            if node.children:
                self._add_flat_subnodes(node, "", "", 0, 0)

    def _add_flat_subnodes(
        self, node: Node, names: str, access_ids: str,
        opt_offset: int, nonopt_offset: int,
    ) -> None:
        # Build name/access path prefix based on node type
        if node.node_type == NodeType.ROOT:
            names += node.name
            access_ids += f"{node.access_id:X}"
        elif node.node_type == NodeType.ARRAY:
            names += node.name
            access_ids += f".{node.access_id:X}"
        elif node.node_type == NodeType.STRUCT_ARRAY:
            names += node.name
            access_ids += f".{node.access_id:X}.1"
        else:
            names += "." + node.name
            access_ids += f".{node.access_id:X}"

        if not node.children:
            # Leaf node — emit VarInfo
            if _is_softdatatype_supported(node.softdatatype):
                info = VarInfo()
                info.name = names
                info.access_sequence = access_ids
                info.softdatatype = node.softdatatype

                if node.node_type == NodeType.ARRAY:
                    info.opt_address = opt_offset
                    info.nonopt_address = nonopt_offset
                else:
                    oi = node.vte.offset_info if node.vte else None
                    info.opt_address = opt_offset + (oi.optimized_address if oi else 0)
                    info.nonopt_address = nonopt_offset + (oi.nonoptimized_address if oi else 0)

                # Bool bitoffset handling
                if node.softdatatype == Softdatatype.BOOL and node.vte:
                    info.opt_bitoffset = node.vte.get_attribute_bitoffset()
                    if node.vte.get_bitoffsetinfo_flag_classic():
                        info.nonopt_bitoffset = node.vte.get_bitoffsetinfo_nonoptimized_bitoffset()
                    else:
                        info.nonopt_bitoffset = node.vte.get_attribute_bitoffset()
                elif node.softdatatype == Softdatatype.BBOOL and node.vte:
                    info.opt_bitoffset = node.vte.get_bitoffsetinfo_optimized_bitoffset()

                self._var_info_list.append(info)
        else:
            # Internal node — accumulate offsets and recurse
            if node.vte is not None:
                oi = node.vte.offset_info
                if node.node_type == NodeType.ARRAY:
                    opt_offset = oi.optimized_address if oi else 0
                    nonopt_offset = oi.nonoptimized_address if oi else 0
                elif node.node_type == NodeType.STRUCT_ARRAY:
                    opt_offset += node.array_adr_offset_opt
                    nonopt_offset += node.array_adr_offset_nonopt
                else:
                    opt_offset += oi.optimized_address if oi else 0
                    nonopt_offset += oi.nonoptimized_address if oi else 0

            for sub in node.children:
                if sub.node_type == NodeType.ARRAY:
                    self._add_flat_subnodes(
                        sub, names, access_ids,
                        opt_offset + sub.array_adr_offset_opt,
                        nonopt_offset + sub.array_adr_offset_nonopt,
                    )
                else:
                    self._add_flat_subnodes(
                        sub, names, access_ids, opt_offset, nonopt_offset,
                    )
