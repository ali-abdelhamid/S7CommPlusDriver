# Condensation Audit — Library Replacements & Cleanup Opportunities

**Scope**: All 33 Python files in `s7commplus/` (6,484 lines)
**Constraint**: Only MIT, Apache 2.0, or BSD licensed libraries
**Date**: 2026-03-26

---

## Summary

After auditing every file, the honest finding is: **this codebase is already lean**. The 55% reduction from C# (14,500 → 6,484 lines) was largely achieved through Python idioms (registry pattern, data-driven maps, `struct.pack`). Most code is S7CommPlus-protocol-specific and cannot be delegated to a generic library.

That said, there are **two genuine library wins**, **several stdlib condensations**, and **dead code to remove**.

---

## 1. Third-Party Library Opportunities

### 1.1 `construct` — Declarative Binary Parsing (MIT)

**What it replaces**: Repetitive `struct.pack`/`struct.unpack_from` sequences with bounds-checking boilerplate.

**Where it helps most**: `protocol/pobject.py` lines 162–292 — the `_deserialize_offset_info()` function. This 130-line function has 16 nearly identical branches, each doing sequences of `decode_uint16_le` / `decode_uint32_le` / `decode_int32_le` calls. With `construct`, each OffsetInfo variant becomes a declarative struct definition.

**Example — current code** (`pobject.py:186–194`):
```python
elif oi_type in (3, 10):
    v1, n = s7p.decode_uint16_le(data, offset); offset += n
    v2, n = s7p.decode_uint16_le(data, offset); offset += n
    oi.extra["unspecified_offsetinfo1"] = v1
    oi.optimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
    oi.nonoptimized_address, n = s7p.decode_uint32_le(data, offset); offset += n
    oi.array_lower_bounds, n = s7p.decode_int32_le(data, offset); offset += n
    oi.array_element_count, n = s7p.decode_uint32_le(data, offset); offset += n
```

**With `construct`**:
```python
Array1Dim = Struct(
    "unspecified_offsetinfo1" / Int16ul,
    Padding(2),
    "optimized_address" / Int32ul,
    "nonoptimized_address" / Int32ul,
    "array_lower_bounds" / Int32sl,
    "array_element_count" / Int32ul,
)
```

**Estimated savings**: ~80 lines in `_deserialize_offset_info()` alone.

**Files affected**: `protocol/pobject.py`

**Risk**: Low — `construct` is mature (v2.10+), widely used, pure Python. Parsing-only change with no serialization impact.

**Verdict**: **RECOMMENDED** — clear win for the most repetitive parsing code.

---

### 1.2 `construct` — Fixed-Width Encode/Decode in `s7p.py` (Same Library)

**What it replaces**: The 26 fixed-width encode/decode wrapper functions in `protocol/s7p.py` (lines 19–175, ~155 lines). Each is a thin 3–4 line wrapper around `struct.pack` / `struct.unpack_from` that adds bounds-checking and returns `(value, bytes_consumed)`.

**Verdict**: **NOT RECOMMENDED**. These wrappers are called from ~100+ sites across the codebase. Replacing them would require touching every message, every value type, and every object parser. The current API (`val, n = s7p.decode_uint32(data, offset); offset += n`) is consistent and easy to audit. The `construct` declarative approach works best for larger structures (like OffsetInfo above), not for scattered single-field reads.

---

### 1.3 No Other Third-Party Libraries Apply

| Library | License | Evaluated For | Verdict |
|---|---|---|---|
| `hexdump` | MIT | `utils.py:hex_dump()` (12 lines) | **SKIP** — not worth adding a dep for 12 lines |
| `bitstring` | MIT | VartypeElement bit-mask helpers | **SKIP** — 5 lines of simple `&` and `>>` |
| `crcmod` | MIT | ItemAddress `symbol_crc` | **SKIP** — CRCs come from PLC, we don't compute them |
| `dpkt` | BSD | TPKT/COTP framing | **SKIP** — packet parsing lib, not bidirectional transport |
| `python-snap7` | LGPL | Transport layer | **SKIP** — wrong protocol (S7Comm, not S7CommPlus) and LGPL |
| `asyncio` | stdlib | Replace threading model | **SKIP** — massive rearchitect for no functional gain |

---

## 2. Stdlib Condensation Opportunities

### 2.1 `@dataclass` for Data Containers

Several classes are pure data holders with hand-written `__init__` methods that just assign defaults. `@dataclass` (stdlib, Python 3.7+) eliminates this boilerplate.

**Candidates** (estimated savings ~40–50 lines total):

| Class | File | Current Lines | With @dataclass |
|---|---|---|---|
| `OffsetInfo` | `protocol/pobject.py:85–117` | 33 lines | ~15 lines |
| `VartypeElement` | `protocol/pobject.py:120–159` | 40 lines | ~25 lines (keeps helper methods) |
| `Node` | `client_api/var_info.py:19–37` | 19 lines | ~10 lines |
| `VarInfo` | `client_api/var_info.py:40–63` | 24 lines | ~12 lines |
| `CommResources` | `client_api/comm_resources.py:18–29` | 12 lines | ~8 lines |

**Example — `VarInfo` current**:
```python
class VarInfo:
    __slots__ = (
        "name", "access_sequence", "softdatatype",
        "opt_address", "opt_bitoffset",
        "nonopt_address", "nonopt_bitoffset",
    )

    def __init__(self) -> None:
        self.name: str = ""
        self.access_sequence: str = ""
        self.softdatatype: int = 0
        self.opt_address: int = 0
        self.opt_bitoffset: int = 0
        self.nonopt_address: int = 0
        self.nonopt_bitoffset: int = 0
```

**With `@dataclass`**:
```python
@dataclass
class VarInfo:
    name: str = ""
    access_sequence: str = ""
    softdatatype: int = 0
    opt_address: int = 0
    opt_bitoffset: int = 0
    nonopt_address: int = 0
    nonopt_bitoffset: int = 0
```

**Note**: `@dataclass(slots=True)` (Python 3.10+) can preserve `__slots__` behavior.

**Verdict**: **RECOMMENDED** — small but clean wins, zero new dependencies.

---

### 2.2 `IntEnum` for Remaining Constant Classes

Several constant classes use plain class attributes where `IntEnum` would provide `.name` for debugging, iteration support, and membership testing.

**Candidates**:

| Class | File | Current Style |
|---|---|---|
| `Quality` | `client_api/plc_tag.py:32–51` | Plain class attrs |
| `LegitimationType` | `auth/legitimation.py:42–44` | Plain class attrs |
| `AccessLevel` | `auth/legitimation.py:47–51` | Plain class attrs |
| `ProtocolVersion` | `protocol/constants.py:15–19` | Plain class attrs |
| `Opcode` | `protocol/constants.py:26–30` | Plain class attrs |
| `FunctionCode` | `protocol/constants.py:37–57` | Plain class attrs |
| `Datatype` | `protocol/constants.py:64–80+` | Plain class attrs |
| `ElementID` | `protocol/constants.py` | Plain class attrs |

**Benefit**: When a response has `function_code=0x054C`, logging shows `FunctionCode.GET_MULTI_VARIABLES` instead of just `1356`. This is especially valuable for debugging protocol issues.

**Risk**: `IntEnum` members compare equal to `int`, so existing `==` comparisons and `dict` keys continue to work. The only breaking change would be code that does `isinstance(x, int)` — but `IntEnum` subclasses `int`, so even that works.

**Verdict**: **RECOMMENDED** — improves debuggability at zero cost.

---

### 2.3 `selectors` Module for Socket Polling

**Current**: `transport/tcp_socket.py` uses `MSG_PEEK` + `setblocking(False/True)` toggling + `time.sleep(0.002)` loop to poll for available data (lines 97–112).

**Better**: The stdlib `selectors` module (or bare `select.select`) can wait for data readability without busy-polling, toggling blocking mode, or peeking.

**Example replacement for `_wait_for_data` and `_bytes_available`**:
```python
import selectors

def _wait_for_data(self, size: int, timeout: float) -> int:
    sel = selectors.DefaultSelector()
    sel.register(self._sock, selectors.EVENT_READ)
    try:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.last_error = ERR_TCP_DATA_RECEIVE
                return self.last_error
            events = sel.select(timeout=remaining)
            if events:
                return 0
    finally:
        sel.unregister(self._sock)
        sel.close()
```

**Estimated savings**: ~20 lines, eliminates `_bytes_available()` entirely, removes blocking-mode toggling (a source of subtle bugs if an exception occurs between `setblocking(False)` and `setblocking(True)`).

**Risk**: Low — `selectors` is stdlib and the standard approach for socket I/O multiplexing.

**Verdict**: **RECOMMENDED** — cleaner, more robust, eliminates potential blocking-mode state bugs.

---

## 3. Dead Code & Unused Imports

### 3.1 `protocol/utils.py` — Unused in Production Code

The 11 functions in `utils.py` (`hex_dump`, `dt_from_value_timestamp`, `get_uint8`, `get_uint16`, `get_uint16_le`, `get_int16`, `get_uint32`, `get_uint32_le`, `get_int32`, `get_float`, `get_double`, `get_utf_string`) are **not imported anywhere in `s7commplus/`**. They are only used in `tests/test_protocol.py`.

The `get_*` accessor functions completely duplicate what `s7p.decode_*` already provides (with the minor difference that `s7p.decode_*` returns `(value, bytes_consumed)` while `get_*` returns just the value).

**Options**:
- **Option A**: Delete `utils.py` entirely, update `test_protocol.py` to use `s7p.decode_*` directly.
- **Option B**: Keep `hex_dump` and `dt_from_value_timestamp` (useful for debugging/future use), delete the 9 `get_*` accessor functions.

**Verdict**: **Option B recommended** — keep the two genuinely useful utilities, remove the redundant byte accessors (~37 lines removed).

---

### 3.2 Unused `BytesIO` Import

Both `protocol/s7p.py` (line 12) and `protocol/values.py` (line 20) import `from io import BytesIO` but never use it anywhere in the file.

**Verdict**: Remove both imports.

---

### 3.3 `notification.py` — Inline `__import__("datetime")`

`messages/notification.py` line 61 uses `__import__("datetime").timedelta(...)` instead of the already-available `datetime.timedelta` (since `datetime` is imported on line 5).

**Verdict**: Replace with `timedelta(microseconds=us)` after adding `timedelta` to the existing import.

---

## 4. Minor Condensation Opportunities

### 4.1 `s7p.py` — Collapse Encode/Decode Functions with a Generator

The 26 fixed-width functions follow two patterns:
- Encode: `buf.extend(struct.pack(FMT, value)); return SIZE`
- Decode: `if bounds_ok: return struct.unpack_from(FMT, data, offset)[0], SIZE; else: return 0, 0`

A factory function could generate all of them:

```python
def _make_codec(fmt: str, size: int):
    def encode(buf: bytearray, value) -> int:
        buf.extend(struct.pack(fmt, value))
        return size
    def decode(data: bytes, offset: int):
        if offset + size > len(data):
            return 0, 0
        return struct.unpack_from(fmt, data, offset)[0], size
    return encode, decode

encode_uint16, decode_uint16 = _make_codec(">H", 2)
encode_int16,  decode_int16  = _make_codec(">h", 2)
encode_uint32, decode_uint32 = _make_codec(">I", 4)
# ... etc
```

**Estimated savings**: ~80 lines (130 → ~50).

**Risk**: Slightly harder to read for newcomers; function signatures in IDE autocomplete show generic params instead of named ones.

**Verdict**: **OPTIONAL** — nice-to-have, not essential. The current explicit functions are easy to audit.

---

### 4.2 Message Classes — Extract Common Response Pattern

Every response class (`CreateObjectResponse`, `ExploreResponse`, `GetMultiVariablesResponse`, etc.) follows the same pattern:
1. `from_pdu(cls, data, offset)` → call `decode_response_pdu_header()`, create instance, call `deserialize()`
2. `deserialize()` → call `decode_response_common()`, read return_value, read type-specific fields, read integrity_id

The `from_pdu` boilerplate could be extracted into a base class or mixin:

```python
class S7pResponse:
    _opcode = Opcode.RESPONSE
    _function_code = 0  # override in subclass

    @classmethod
    def from_pdu(cls, data, offset=0, **kwargs):
        proto_ver, offset = decode_response_pdu_header(
            data, offset, cls._opcode, cls._function_code
        )
        resp = cls(proto_ver, **kwargs)
        resp.deserialize(data, offset)
        return resp
```

**Estimated savings**: ~50 lines across 8 response classes (each saves ~6 lines of `from_pdu` boilerplate).

**Verdict**: **OPTIONAL** — reduces repetition but adds indirection. Current code is explicit and easy to follow.

---

## 5. What MUST Stay Bespoke

For completeness, these modules have **no library replacement** — they implement S7CommPlus-specific logic:

| Module | Why it must stay |
|---|---|
| `protocol/s7p.py` (VLQ functions) | Non-standard VLQ with bit-6 sign flag — no library implements this |
| `protocol/values.py` | S7CommPlus wire format with custom flags byte + registry dispatch |
| `protocol/pobject.py` (decode_object, PObject) | Recursive S7CommPlus object tree with VarType/VarName lists |
| `protocol/constants.py` | Siemens-specific protocol IDs, softdatatypes, function codes |
| `protocol/errors.py` | S7CommPlus-specific error code namespace |
| All `messages/*.py` | Each message has unique field layout per S7CommPlus spec |
| `transport/cotp.py` | TPKT/COTP is standardized (RFC 1006) but no MIT/BSD standalone Python lib exists |
| `transport/tls.py` | Already uses stdlib `ssl.MemoryBIO` — as lean as possible |
| `transport/client.py` | Orchestrates S7CommPlus-specific TCP→COTP→TLS→callback pipeline |
| `client_api/browser.py` | S7CommPlus-specific tree building with BBOOL padding, struct arrays, etc. |
| `client_api/plc_tag.py` | S7CommPlus softdatatype → PValue mapping, BCD encoding |
| `client_api/var_info.py` | S7CommPlus-specific data structures |
| `client_api/comm_resources.py` | Reads S7CommPlus-specific SystemLimits LIDs |
| `auth/legitimation.py` | S7CommPlus-specific auth protocol (already uses `cryptography` lib) |
| `connection.py` | S7CommPlus 7-step handshake, PDU framing, integrity counters |

---

## 6. Prioritized Action List

| # | Change | Type | Est. Lines Saved | Effort | Risk |
|---|---|---|---|---|---|
| 1 | Remove dead `get_*` accessors from `utils.py` | Dead code | ~37 | Low | None |
| 2 | Remove unused `BytesIO` imports from `s7p.py` and `values.py` | Dead code | 2 | Trivial | None |
| 3 | Fix `__import__("datetime")` in `notification.py` | Bug/smell | 1 | Trivial | None |
| 4 | Convert data containers to `@dataclass` | Stdlib | ~40–50 | Low | Low |
| 5 | Convert constant classes to `IntEnum` | Stdlib | ~0 (but better debugging) | Low | Low |
| 6 | Replace socket polling with `selectors` | Stdlib | ~20 | Medium | Low |
| 7 | Use `construct` for OffsetInfo parsing | Third-party | ~80 | Medium | Low |
| 8 | Collapse encode/decode with factory | Refactor | ~80 | Medium | Low |
| 9 | Extract response `from_pdu` base class | Refactor | ~50 | Medium | Low |

Items 1–3 are pure cleanup with zero risk. Items 4–6 are stdlib improvements. Item 7 is the only third-party library addition that genuinely pays for itself. Items 8–9 are optional refactors.
