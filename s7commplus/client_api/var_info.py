"""Variable info and browser tree structures.

Ported from Browser.cs — Node, VarRoot, VarInfo, eNodeType.
"""

from __future__ import annotations

from enum import IntEnum


class NodeType(IntEnum):
    """Classification of browser tree nodes."""

    UNDEFINED = 0
    ROOT = 1
    VAR = 2
    ARRAY = 3
    STRUCT_ARRAY = 4


class Node:
    """Tree node used internally by Browser to represent a variable or array element."""

    __slots__ = (
        "node_type", "name", "access_id", "softdatatype",
        "relation_id", "vte", "array_adr_offset_opt",
        "array_adr_offset_nonopt", "children",
    )

    def __init__(self) -> None:
        """Initialize an empty Node with default values."""
        self.node_type: int = NodeType.UNDEFINED
        self.name: str = ""
        self.access_id: int = 0
        self.softdatatype: int = 0
        self.relation_id: int = 0
        self.vte = None               # VartypeElement | None
        self.array_adr_offset_opt: int = 0
        self.array_adr_offset_nonopt: int = 0
        self.children: list[Node] = []


class VarInfo:
    """Output of Browser — one browsable variable with its access path and offsets."""

    __slots__ = (
        "name", "access_sequence", "softdatatype",
        "opt_address", "opt_bitoffset",
        "nonopt_address", "nonopt_bitoffset",
    )

    def __init__(self) -> None:
        """Initialize an empty VarInfo with default values."""
        self.name: str = ""
        self.access_sequence: str = ""
        self.softdatatype: int = 0
        self.opt_address: int = 0
        self.opt_bitoffset: int = 0
        self.nonopt_address: int = 0
        self.nonopt_bitoffset: int = 0

    def __repr__(self) -> str:
        """Return a debug-friendly string representation.

        Returns:
            Human-readable string with name, access sequence, and offsets.
        """
        return (
            f"VarInfo(name={self.name!r}, access={self.access_sequence!r}, "
            f"sdt={self.softdatatype}, opt={self.opt_address}:{self.opt_bitoffset}, "
            f"nonopt={self.nonopt_address}:{self.nonopt_bitoffset})"
        )
