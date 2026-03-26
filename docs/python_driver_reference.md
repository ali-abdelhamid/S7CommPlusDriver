# S7CommPlus Python Driver — Reference Guide

**Source**: Python port of [thomas-v2/S7CommPlusDriver](https://github.com/thomas-v2/S7CommPlusDriver) (C#)
**Python codebase**: 6,484 lines across 33 files, 451 tests
**Target**: Siemens S7-1200/1500 PLCs via S7CommPlus over TLS 1.3

---

## 1. Python Module Structure at a Glance

```
s7commplus/                              6,484 lines total
├── __init__.py                    8 lines   ← Public re-exports
├── connection.py                624 lines   ← ORCHESTRATOR (connect, read/write, PDU framing)
│
├── transport/                   952 lines   ← TRANSPORT LAYER
│   ├── tcp_socket.py            203 lines   ← Raw TCP socket wrapper (MsgSocket)
│   ├── cotp.py                  203 lines   ← TPKT/COTP framing (ISO-on-TCP)
│   ├── tls.py                   225 lines   ← TLS 1.3 via ssl.MemoryBIO
│   └── client.py                321 lines   ← S7Client: TCP → COTP → TLS orchestrator
│
├── protocol/                  2,476 lines   ← PROTOCOL SERIALIZATION & TYPES
│   ├── s7p.py                   454 lines   ← VLQ encoding/decoding, object deserialization
│   ├── values.py                775 lines   ← PValue type hierarchy (50+ types, registry pattern)
│   ├── pobject.py               576 lines   ← PObject, ItemAddress, VartypeElement, OffsetInfo
│   ├── constants.py             418 lines   ← Ids, FunctionCode, Opcode, Softdatatype, etc.
│   ├── errors.py                178 lines   ← Error codes and exception classes
│   └── utils.py                  75 lines   ← Hex dump and byte utilities
│
├── messages/                    937 lines   ← PROTOCOL MESSAGES (request/response pairs)
│   ├── base.py                   73 lines   ← S7pRequest / S7pResponse ABCs
│   ├── init_ssl.py               61 lines   ← InitSslRequest / InitSslResponse
│   ├── create_object.py          97 lines   ← CreateObjectRequest / CreateObjectResponse
│   ├── delete_object.py          73 lines   ← DeleteObjectRequest / DeleteObjectResponse
│   ├── explore.py                91 lines   ← ExploreRequest / ExploreResponse
│   ├── get_multi_variables.py    87 lines   ← GetMultiVariablesRequest / Response
│   ├── set_multi_variables.py   102 lines   ← SetMultiVariablesRequest / Response
│   ├── set_variable.py           70 lines   ← SetVariableRequest / SetVariableResponse
│   ├── get_var_substreamed.py    73 lines   ← GetVarSubstreamedRequest / Response
│   ├── notification.py          107 lines   ← Subscription notification deserialization
│   ├── system_event.py           72 lines   ← Protocol error / system event handling
│   └── __init__.py               31 lines   ← Re-exports all request/response classes
│
├── client_api/                1,113 lines   ← HIGH-LEVEL API
│   ├── browser.py               381 lines   ← Browser: tree builder → flat VarInfo list
│   ├── plc_tag.py               574 lines   ← PlcTag type system, tag_factory, read/write_tags
│   ├── var_info.py               63 lines   ← Node, NodeType, VarInfo data structures
│   └── comm_resources.py         95 lines   ← CommResources: PLC system limits
│
└── auth/                        373 lines   ← AUTHENTICATION
    └── legitimation.py          372 lines   ← Legacy (SHA1-XOR) and New (AES-256-CBC) auth
```

---

## 2. Dependency Map — What Calls What

```
User Code
 │
 ▼
S7CommPlusConnection  (connection.py)              ← THE ORCHESTRATOR
 │  Owns: S7Client, CommResources
 │  State: session_id, sequence_number, integrity counters
 │  Key methods: connect(), disconnect(), read_values(), write_values(),
 │               send_request(), wait_for_response()
 │
 ├──▶ S7Client  (transport/client.py)               ← TRANSPORT ORCHESTRATOR
 │    │  Owns: MsgSocket, COTPTransport, TLSOverCOTP
 │    │  Threading: background daemon thread reads COTP frames continuously
 │    │  Methods: connect(), disconnect(), send(), ssl_activate(),
 │    │           get_oms_exporter_secret()
 │    │
 │    ├──▶ MsgSocket  (transport/tcp_socket.py)      ← RAW TCP
 │    │    Uses: socket.socket (AF_INET, SOCK_STREAM, TCP_NODELAY)
 │    │    Methods: connect(), send(), receive(), close()
 │    │    Pattern: blocking I/O with poll-based timeout (2ms interval)
 │    │
 │    ├──▶ COTPTransport  (transport/cotp.py)        ← ISO-ON-TCP FRAMING
 │    │    Uses: MsgSocket for raw byte I/O
 │    │    Methods: iso_connect(), send_iso_packet(), recv_iso_packet()
 │    │    Pattern: TPKT (4B) + COTP-DT (3B) header wrapping
 │    │    TSAP: remote="SIMATIC-ROOT-HMI", local=0x0600
 │    │
 │    └──▶ TLSOverCOTP  (transport/tls.py)           ← TLS 1.3
 │         Uses: ssl.MemoryBIO + ssl.SSLObject (no raw socket access)
 │         Uses: COTPTransport for encrypted frame I/O
 │         Methods: handshake(), send(), recv(), export_keying_material()
 │         Pattern: BIO memory buffers — encrypted bytes shuttled through
 │                  COTP frames, not directly on TCP socket
 │         Config: TLS 1.3 only, GCM cipher suites, no cert verification
 │
 ├──▶ Messages  (messages/*.py)                      ← PROTOCOL MESSAGES
 │    │  All inherit S7pRequest or S7pResponse (messages/base.py)
 │    │  All use s7p.encode_*/decode_* for serialization
 │    │
 │    ├── InitSslRequest / Response                  ← Step 1: pre-TLS init
 │    ├── CreateObjectRequest / Response             ← Step 3: create session
 │    ├── SetMultiVariablesRequest / Response        ← Step 4: session setup + batch writes
 │    ├── GetMultiVariablesRequest / Response        ← Batch reads
 │    ├── SetVariableRequest / Response              ← Single writes + auth response
 │    ├── GetVarSubstreamedRequest / Response        ← System queries + auth challenge
 │    ├── ExploreRequest / Response                  ← Browse/discover PLC objects
 │    ├── DeleteObjectRequest / Response             ← Session teardown
 │    ├── Notification                               ← Subscription push data
 │    └── SystemEvent                                ← Fatal/non-fatal protocol errors
 │
 ├──▶ s7p  (protocol/s7p.py)                        ← SERIALIZATION ENGINE
 │    Static functions:
 │    ├── encode_byte / decode_byte                  (fixed 8-bit)
 │    ├── encode_uint16 / decode_uint16              (big-endian 16-bit)
 │    ├── encode_uint32 / decode_uint32              (big-endian 32-bit)
 │    ├── encode_uint64 / decode_uint64              (big-endian 64-bit)
 │    ├── encode_uint16_le / decode_uint16_le        (little-endian 16-bit)
 │    ├── encode_uint32_vlq / decode_uint32_vlq      (variable-length quantity)
 │    ├── encode_int32_vlq / decode_int32_vlq        (signed VLQ, bit 6 = sign)
 │    ├── encode_uint64_vlq / decode_uint64_vlq      (64-bit VLQ)
 │    ├── decode_object / decode_object_list          (recursive PObject parser)
 │    └── encode_object_qualifier                    (standard object qualifier)
 │
 ├──▶ PValue hierarchy  (protocol/values.py)         ← VALUE TYPE SYSTEM
 │    │  Abstract base: PValue (flags, datatype tag, serialize/deserialize)
 │    │  Registry pattern: @_register(datatype, kind) → dispatch table
 │    │  PValue.deserialize(data, offset) reads flags+tag, dispatches to subclass
 │    │
 │    ├── Scalars:  ValueBool, ValueByte, ValueUSInt, ValueUInt, ValueUDInt,
 │    │             ValueULInt, ValueSInt, ValueInt, ValueDInt, ValueLInt,
 │    │             ValueWord, ValueDWord, ValueLWord, ValueReal, ValueLReal,
 │    │             ValueTimestamp, ValueTimespan, ValueRID, ValueAID,
 │    │             ValueBlob, ValueWString, ValueNull
 │    ├── Arrays:   Value{Type}Array for each scalar type
 │    ├── Sparse:   ValueUDIntSparseArray, ValueDIntSparseArray,
 │    │             ValueBlobSparseArray, ValueWStringSparseArray
 │    └── Struct:   ValueStruct (recursive, keyed by UInt32 element IDs)
 │
 ├──▶ PObject  (protocol/pobject.py)                 ← PROTOCOL OBJECT MODEL
 │    │  Fields: relation_id, class_id, class_flags, attribute_id
 │    │  Contains: attributes (dict[int, PValue])
 │    │            objects (dict[tuple, PObject])  — children
 │    │            relations (dict[int, int])
 │    │            vartype_list (VartypeList)
 │    │            varname_list (VarnameList)
 │    │
 │    ├── ItemAddress                                ← Symbolic variable address
 │    │   Fields: area, sub_area, lid (list[int]), symbol_crc
 │    │   Used by: read_values(), write_values() to identify PLC variables
 │    │
 │    ├── VartypeElement                             ← Single variable type descriptor
 │    │   Fields: lid, softdatatype, offset_info, attribute_flags, bitoffsetinfo_flags
 │    │   Helpers: get_attribute_bitoffset(), get_attribute_section(),
 │    │            get_bitoffsetinfo_flag_classic(), etc.
 │    │
 │    └── OffsetInfo                                 ← Address/offset metadata
 │        Fields: optimized_address, nonoptimized_address, relation_id,
 │                array_element_count, array_lower_bounds, mdim_element_counts
 │        Methods: has_relation(), is_1dim(), is_mdim()
 │
 ├──▶ Browser  (client_api/browser.py)               ← SYMBOL TREE BUILDER
 │    │  Input:  block nodes (DBs, I/Q/M areas) + type-info PObjects
 │    │  Phase 1: build_tree() — matches blocks to type info via relation_id,
 │    │           walks VartypeList/VarnameList → builds Node tree
 │    │  Phase 2: build_flat_list() — depth-first walk → flat list[VarInfo]
 │    │
 │    │  Handles: 1D arrays, MDim arrays, struct arrays, BBOOL MDim padding,
 │    │           Bool bitoffset, String/WString sizing, nested structs
 │    │
 │    ├── Node  (client_api/var_info.py)             ← Internal tree node
 │    │   Fields: node_type, name, access_id, softdatatype, children, vte
 │    │
 │    ├── NodeType  (client_api/var_info.py)          ← Node classification
 │    │   Values: ROOT=1, VAR=2, ARRAY=3, STRUCT_ARRAY=4
 │    │
 │    └── VarInfo  (client_api/var_info.py)           ← Output: one browsable variable
 │        Fields: name, access_sequence, softdatatype,
 │                opt_address, opt_bitoffset, nonopt_address, nonopt_bitoffset
 │
 ├──▶ PlcTag / tag_factory / read_tags / write_tags  ← USER-FACING TYPE LAYER
 │    │  (client_api/plc_tag.py)
 │    │
 │    │  PlcTag base: name, address (ItemAddress), softdatatype, value, quality
 │    │  13 specialized subclasses: PlcTagChar, PlcTagWChar, PlcTagString,
 │    │    PlcTagWString, PlcTagDate, PlcTagTimeOfDay, PlcTagTime, PlcTagS5Time,
 │    │    PlcTagDateAndTime, PlcTagLTime, PlcTagLTOD, PlcTagLDT, PlcTagDTL,
 │    │    PlcTagRawBytes
 │    │  47 simple types via data-driven _SIMPLE_TAG_MAP dict
 │    │
 │    │  tag_factory(name, address, softdatatype) → PlcTag | None
 │    │  read_tags(connection, tags)  → batch read via connection.read_values()
 │    │  write_tags(connection, tags) → batch write via connection.write_values()
 │    │
 │    └── Quality  (client_api/plc_tag.py)           ← OPC DA quality codes
 │        Constants: BAD=0x00, UNCERTAIN=0x40, GOOD=0xC0, etc.
 │
 ├──▶ CommResources  (client_api/comm_resources.py)  ← PLC SYSTEM LIMITS
 │    Fields: tags_per_read_max, tags_per_write_max,
 │            plc_subscriptions_max, plc_attributes_max, etc.
 │    Methods: read_max(conn), read_free(conn)
 │
 └──▶ legitimate  (auth/legitimation.py)             ← AUTHENTICATION
      Two paths based on firmware version:
      ├── _legitimate_legacy(): SHA1(password) XOR challenge → SetVariable
      └── _legitimate_new():  OMS exporter secret → SHA256 key rolling →
                              AES-256-CBC encrypt(payload, key, iv=challenge[:16])
      Helpers: _sha256(), _sha1(), _encrypt_aes_cbc(), _build_legitimation_payload()
      Constants: LegitimationType (LEGACY=1, NEW=2), AccessLevel (FULL=1..NO=4)
```

### Inter-module dependency summary

```
connection.py ──────────┬──▶ transport/client.py ──▶ transport/cotp.py ──▶ transport/tcp_socket.py
                        │                          ──▶ transport/tls.py  ──▶ transport/cotp.py
                        ├──▶ messages/*.py ──────────▶ protocol/s7p.py
                        │                            ──▶ protocol/values.py
                        │                            ──▶ protocol/constants.py
                        ├──▶ protocol/values.py
                        ├──▶ protocol/pobject.py ────▶ protocol/s7p.py
                        ├──▶ protocol/constants.py
                        ├──▶ protocol/errors.py
                        ├──▶ auth/legitimation.py ──▶ protocol/values.py
                        │                          ──▶ protocol/constants.py
                        │                          ──▶ messages/*.py
                        └──▶ client_api/comm_resources.py ──▶ protocol/pobject.py
                                                           ──▶ protocol/values.py

client_api/browser.py ──▶ protocol/constants.py
                       ──▶ protocol/pobject.py (VartypeElement, PObject)
                       ──▶ client_api/var_info.py

client_api/plc_tag.py ──▶ protocol/constants.py (Softdatatype)
                       ──▶ protocol/pobject.py (ItemAddress)
                       ──▶ protocol/values.py (PValue subclasses)
                       ──▶ connection.py (read_values, write_values — duck typed)
```

---

## 3. Connection Lifecycle (Python)

### 3.1 The 7-Step Handshake

```
conn = S7CommPlusConnection()
err = conn.connect("192.168.1.30", password="secret")
│
├─ Step 0: TCP + COTP
│  ├─ S7Client.connect()
│  │   ├─ MsgSocket.connect("192.168.1.30", 102) → raw TCP
│  │   └─ COTPTransport.iso_connect() → CR/CC exchange
│  │       Remote TSAP = b"SIMATIC-ROOT-HMI"
│  └─ Starts background daemon thread (_run_loop)
│     Thread continuously reads COTP packets, dispatches via on_data_received callback
│
├─ Step 1: InitSSL (unencrypted, ProtocolVersion.V1)
│  ├─ conn.send_request(InitSslRequest)
│  └─ InitSslResponse.from_pdu(conn.wait_for_response())
│
├─ Step 2: TLS Activation
│  ├─ S7Client.ssl_activate()
│  │   ├─ TLSOverCOTP(cotp, keylog_file=...)
│  │   ├─ Creates ssl.SSLContext: TLS 1.3 only, no cert verify, GCM ciphers
│  │   ├─ Creates ssl.SSLObject with MemoryBIO pair (incoming + outgoing)
│  │   └─ TLSOverCOTP.handshake() — drives TLS over COTP frames
│  ══════════ ALL TRAFFIC FROM HERE IS TLS-ENCRYPTED ══════════
│
├─ Step 3: CreateObject (ProtocolVersion.V1, encrypted)
│  ├─ conn.send_request(CreateObjectRequest)
│  ├─ CreateObjectResponse.from_pdu(conn.wait_for_response())
│  ├─ Extracts session_id and session_id2 from response
│  └─ Extracts server_session ValueStruct (firmware info, PAOM string)
│
├─ Step 4: SetMultiVariables (ProtocolVersion.V2)
│  ├─ conn.send_request(SetMultiVariablesRequest)
│  │   Request echoes back server session parameters
│  └─ SetMultiVariablesResponse.from_pdu(conn.wait_for_response())
│
├─ Step 5: Read System Limits
│  └─ CommResources.read_max(conn)
│     Reads via GetMultiVariables from ObjectRoot/SystemLimits:
│       LID 1000 → tags_per_read_max
│       LID 1001 → tags_per_write_max
│       LID 0    → plc_subscriptions_max
│       LID 1    → plc_attributes_max
│       LID 2    → subscription_memory_max
│
└─ Step 6: Legitimation
   └─ legitimate(conn, server_session, password, username)
      ├─ Parses firmware version from PAOM string
      ├─ Reads EffectiveProtectionLevel via GetVarSubstreamed
      └─ If password needed:
         ├─ Legacy (FW < 3.1): SHA1(password) XOR 20-byte challenge → SetVariable
         └─ New (FW >= 3.1):
            ├─ Get OMS secret: TLSOverCOTP.export_keying_material("EXPERIMENTAL_OMS")
            ├─ Key = SHA256(oms_secret), IV = challenge[:16]
            └─ AES-256-CBC encrypt(payload) → SetVariable
```

### 3.2 Disconnect

```
conn.disconnect()
│
├─ Sends DeleteObjectRequest for session_id
│  └─ DeleteObjectResponse — clears session state
└─ S7Client.disconnect()
   ├─ Signals background thread to stop (_stop_event.set())
   ├─ Joins thread (5s timeout)
   └─ MsgSocket.close() — TCP shutdown
```

### 3.3 Threading Model

```
┌──────────────────────────────────────────────────────────────────┐
│ Main Thread                    │ Background Thread               │
│                                │ (S7Client._run_loop, daemon)    │
│ conn.send_request(req)         │                                 │
│   → serialize → S7Client.send  │                                 │
│   → TLS encrypt → COTP send   │                                 │
│                                │ COTP recv → TLS decrypt          │
│                                │ → conn._on_data_received(pdu)   │
│                                │   → reassemble fragments        │
│                                │   → deque.append(complete_pdu)  │
│                                │   → pdu_event.set()             │
│ conn.wait_for_response()       │                                 │
│   → pdu_event.wait()           │                                 │
│   → deque.popleft()            │                                 │
│   → Response.from_pdu(data)    │                                 │
└──────────────────────────────────────────────────────────────────┘

Synchronization: threading.Lock protects the deque
                 threading.Event signals new PDU arrival
```

---

## 4. Browse Workflow (Discover All Tags)

```
# User code (after connect):
browser = Browser()

# Phase 1: Explore PLC program root
req = ExploreRequest(...)
req.explore_id = Ids.NATIVE_OBJECTS_THE_PLC_PROGRAM_RID
# → Returns list of PObjects (one per DB, FC, FB, etc.)
# → Filter by ClassId == DB_Class_Rid → extract db_name, db_number, ti_relid

# Phase 2: For each data block
browser.add_block_node(NodeType.ROOT, "MyDB", access_id=0x8A0E0001, ti_rel_id=relid)

# Phase 3: Add I/Q/M/Timer/Counter areas (hard-coded access IDs)
browser.add_block_node(NodeType.ROOT, "IArea", access_id=0x90010000, ti_rel_id=...)
browser.add_block_node(NodeType.ROOT, "QArea", access_id=0x90020000, ti_rel_id=...)
browser.add_block_node(NodeType.ROOT, "MArea", access_id=0x90030000, ti_rel_id=...)

# Phase 4: Explore TypeInfoContainer (one large request, possibly fragmented)
req = ExploreRequest(...)
req.explore_id = Ids.OBJECT_OMS_TYPE_INFO_CONTAINER
# → Returns the entire type information tree
browser.set_type_info_objects(type_info_objects)

# Phase 5: Build tree and flatten
browser.build_tree()
#   For each root node, finds matching PObject by relation_id
#   Walks VartypeList + VarnameList → builds Node tree
#   Handles: scalars, 1D arrays, MDim arrays, struct arrays,
#            BBOOL padding, Bool bitoffsets, String/WString sizing

browser.build_flat_list()
#   Depth-first walk → flat list of VarInfo entries

for info in browser.var_info_list:
    print(f"{info.name}  access={info.access_sequence}  "
          f"sdt={info.softdatatype}  opt_addr={info.opt_address}")
```

**Example output:**

```
MyDB.Temperature     access=8A0E0001.1   sdt=8   opt_addr=0
MyDB.Pressure        access=8A0E0001.2   sdt=8   opt_addr=4
MyDB.ValveOpen       access=8A0E0001.3   sdt=1   opt_addr=8
MyDB.Readings[0]     access=8A0E0001.4.0 sdt=8   opt_addr=10
MyDB.Readings[1]     access=8A0E0001.4.1 sdt=8   opt_addr=14
MyDB.Name            access=8A0E0001.5   sdt=19  opt_addr=18
```

### Browser tree structure (internal)

```
Node(ROOT, "MyDB", access_id=0x8A0E0001)
 ├── Node(VAR, "Temperature", access_id=1, sdt=REAL)        → VarInfo leaf
 ├── Node(VAR, "Pressure", access_id=2, sdt=REAL)           → VarInfo leaf
 ├── Node(VAR, "ValveOpen", access_id=3, sdt=BOOL)          → VarInfo leaf
 ├── Node(VAR, "Readings", access_id=4, sdt=REAL)           ← 1D array parent
 │    ├── Node(ARRAY, "[0]", access_id=0, offset_opt=0)     → VarInfo leaf
 │    ├── Node(ARRAY, "[1]", access_id=1, offset_opt=4)     → VarInfo leaf
 │    └── Node(ARRAY, "[2]", access_id=2, offset_opt=8)     → VarInfo leaf
 └── Node(VAR, "Actuator", access_id=5)                     ← Struct parent
      ├── Node(VAR, "Speed", access_id=1, sdt=INT)          → VarInfo leaf
      └── Node(VAR, "Active", access_id=2, sdt=BOOL)        → VarInfo leaf
```

---

## 5. Read/Write Workflow

### 5.1 Low-Level: `connection.read_values()` / `connection.write_values()`

```
values, errors, result = conn.read_values(address_list)
│
├─ Splits addresses into chunks of comm_resources.tags_per_read_max
├─ For each chunk:
│   ├─ Build GetMultiVariablesRequest with list of ItemAddress
│   │   ItemAddress = { area=0x8A0E0001 (DB1), sub_area=DB_ValueActual,
│   │                   lid=[0x1] (variable at LID 1) }
│   ├─ conn.send_request(req)
│   │   → sets session_id, sequence_number, integrity_id
│   │   → serializes → S7CommPlus PDU → fragments if > max_size
│   │   → sends through TLS → COTP → TCP
│   ├─ conn.wait_for_response()
│   │   → blocks until background thread delivers complete PDU
│   ├─ GetMultiVariablesResponse.from_pdu(pdu_data)
│   │   → deserializes values + error codes
│   └─ _check_response_integrity(req, resp)
│       → validates sequence_number and integrity_id match
└─ Returns (values: list[PValue|None], errors: list[int], result: int)


errors, result = conn.write_values(address_list, value_list)
│  Same pattern but uses SetMultiVariablesRequest
│  value_list contains PValue instances: ValueInt(42), ValueReal(3.14), etc.
└─ Returns (errors: list[int], result: int)
```

### 5.2 High-Level: `read_tags()` / `write_tags()`

```
result = read_tags(connection, tags)
│
├─ Extracts addresses: [tag.address for tag in tags]
├─ Calls connection.read_values(addresses)
│   → returns (values, errors, result)
└─ For each tag:
    tag.process_read_result(values[i], errors[i])
    → Specialized subclasses decode the PValue:
       PlcTag (base):      tag.value = pvalue.value
       PlcTagChar:          tag.value = bytes([pvalue.value]).decode("iso-8859-1")
       PlcTagString:        tag.value = decode S7 string header (max_len, act_len, bytes)
       PlcTagDate:          tag.value = datetime(1990,1,1) + timedelta(days=pvalue.value)
       PlcTagDateAndTime:   tag.value = BCD-decode 8 bytes → datetime
       PlcTagDTL:           tag.value = extract from ValueStruct → datetime
       PlcTagS5Time:        tag.time_value = BCD decode, tag.time_base = extract
    → Sets tag.quality = Quality.GOOD (0xC0) or Quality.BAD (0x00)


result = write_tags(connection, tags)
│
├─ Extracts addresses: [tag.address for tag in tags]
├─ Extracts PValues: [tag.get_write_value() for tag in tags]
│   → Specialized subclasses encode the value:
│      PlcTag (base):      _write_cls(self.value)  e.g. ValueInt(42)
│      PlcTagChar:          ValueUSInt(char.encode("iso-8859-1")[0])
│      PlcTagString:        ValueUSIntArray([max_len, act_len, *bytes])
│      PlcTagDate:          ValueUInt((date - epoch).days)
│      PlcTagDTL:           ValueStruct with 12-byte payload
├─ Calls connection.write_values(addresses, pvalues)
└─ For each tag:
    tag.process_write_result(errors[i])
```

---

## 6. PDU Framing and Fragmentation

```
┌──────────────────────────────────────────────────────────────────┐
│                      Network Stack                               │
│                                                                  │
│  ┌─ TCP ──────────────────────────────────────────────────────┐  │
│  │  ┌─ TPKT (4B) ─────────────────────────────────────────┐  │  │
│  │  │  03 00 [total_len]                                   │  │  │
│  │  │  ┌─ COTP-DT (3B) ────────────────────────────────┐  │  │  │
│  │  │  │  02 F0 80                                      │  │  │  │
│  │  │  │  ┌─ TLS 1.3 Record ────────────────────────┐  │  │  │  │
│  │  │  │  │  ┌─ S7CommPlus PDU ──────────────────┐  │  │  │  │  │
│  │  │  │  │  │  Header: 72 [proto_ver] [data_len] │  │  │  │  │  │
│  │  │  │  │  │  Data:   [serialized request/resp] │  │  │  │  │  │
│  │  │  │  │  │  Trailer: 72 [proto_ver] 00 00     │  │  │  │  │  │
│  │  │  │  │  └───────────────────────────────────┘  │  │  │  │  │
│  │  │  │  └─────────────────────────────────────────┘  │  │  │  │
│  │  │  └───────────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘

Max payload per fragment: 1024 - 37 = 987 bytes
  (1024 = negotiated ISO PDU size)
  (37 = 4 TPKT + 3 COTP + 5 TLS hdr + 17 TLS overhead + 4 S7+ hdr + 4 S7+ trailer)

Fragmentation: if serialized data > 987 bytes, split into multiple PDUs.
  - Each fragment has a 4-byte header (magic + proto_ver + data_len)
  - Only the LAST fragment has the 4-byte trailer (magic + proto_ver + 0x0000)
  - Receiver reassembles in _on_data_received() by checking if (pdu_len - 8) == data_len
```

---

## 7. Key Design Patterns

### 7.1 Registry/Factory Pattern (PValue types)

```python
# In protocol/values.py:
_REGISTRY: dict[tuple[int, int], type] = {}

def _register(datatype: int, kind: int = 0):
    def decorator(cls):
        _REGISTRY[(datatype, kind)] = cls
        return cls
    return decorator

@_register(Datatype.INT, kind=0)
class ValueInt(PValue):
    def __init__(self, value: int = 0): ...
    def serialize(self, buf: bytearray) -> None: ...

# Deserialization dispatches automatically:
pvalue = PValue.deserialize(data, offset)  # → correct ValueXxx subclass
```

### 7.2 Data-Driven Tag Factory (PlcTag types)

```python
# In client_api/plc_tag.py:
# 47 softdatatypes mapped to PValue classes via a single dict
_SIMPLE_TAG_MAP = {
    Softdatatype.BOOL:  (ValueBool,  ValueBoolArray),
    Softdatatype.INT:   (ValueInt,   ValueIntArray),
    Softdatatype.REAL:  (ValueReal,  ValueRealArray),
    # ... 44 more entries
}

# 13 specialized subclasses handle complex types (BCD, strings, structs)
# tag_factory() checks specialized types first, then falls back to the map
tag = tag_factory("Temperature", address, Softdatatype.REAL)  # → PlcTag
tag = tag_factory("Name", address, Softdatatype.STRING)       # → PlcTagString
tag = tag_factory("Timestamp", address, Softdatatype.DTL)     # → PlcTagDTL
```

### 7.3 Dual Integrity Counters

```python
# In connection.py:
# SET-type function codes (writes, creates, deletes) use integrity_id_set
# GET-type function codes (reads, explores) use integrity_id
# Both counters are independent and wrap at 0xFFFFFFFF

_SET_FUNCTION_CODES = frozenset({
    FunctionCode.SET_MULTI_VARIABLES,
    FunctionCode.SET_VARIABLE,
    FunctionCode.SET_VAR_SUB_STREAMED,
    FunctionCode.DELETE_OBJECT,
    FunctionCode.CREATE_OBJECT,
})
```

### 7.4 Callback-Based I/O (Transport ↔ Connection)

```python
# S7Client sets a callback during connect:
self._client.on_data_received = self._on_data_received

# Background thread invokes it when data arrives:
# S7Client._run_loop() → TLS decrypt → callback(plaintext, length)

# Connection reassembles fragments and queues complete PDUs:
# _on_data_received() → validate magic → append to deque → pdu_event.set()
```

---

## 8. Usage Examples

### 8.1 Connecting to a PLC

```python
from s7commplus.connection import S7CommPlusConnection

conn = S7CommPlusConnection()

# Basic connection (no password)
err = conn.connect("192.168.1.30")
if err != 0:
    print(f"Connection failed with error code: {err}")
    raise SystemExit(1)

# Connection with password and TLS key logging
err = conn.connect(
    "192.168.1.30",
    password="my_plc_password",
    timeout_ms=10000,
    keylog_file="/tmp/s7plus_keys.log",   # for Wireshark analysis
)

# ... use connection ...

conn.disconnect()
```

### 8.2 Reading Variables (Low-Level)

```python
from s7commplus.protocol.pobject import ItemAddress

# Build addresses for variables to read
addr1 = ItemAddress(area=0x8A0E0001, sub_area=0x9F6)  # DB1
addr1.lid = [0x1]  # LID of "Temperature" variable

addr2 = ItemAddress(area=0x8A0E0001, sub_area=0x9F6)
addr2.lid = [0x2]  # LID of "Pressure" variable

# Read multiple variables in one call
values, errors, result = conn.read_values([addr1, addr2])

if result == 0:
    for i, (val, err) in enumerate(zip(values, errors)):
        if err == 0 and val is not None:
            print(f"Variable {i}: {val.value}")
        else:
            print(f"Variable {i}: read error {err}")
```

### 8.3 Writing Variables (Low-Level)

```python
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.protocol.values import ValueReal, ValueBool

addr_temp = ItemAddress(area=0x8A0E0001, sub_area=0x9F6)
addr_temp.lid = [0x1]

addr_valve = ItemAddress(area=0x8A0E0001, sub_area=0x9F6)
addr_valve.lid = [0x3]

errors, result = conn.write_values(
    [addr_temp, addr_valve],
    [ValueReal(72.5), ValueBool(True)],
)

if result == 0:
    for i, err in enumerate(errors):
        if err != 0:
            print(f"Write error on variable {i}: {err}")
```

### 8.4 Using PlcTag (High-Level)

```python
from s7commplus.protocol.pobject import ItemAddress
from s7commplus.client_api.plc_tag import (
    PlcTag, Quality, tag_factory, read_tags, write_tags,
)
from s7commplus.protocol.constants import Softdatatype

# Create tags via the factory
addr = ItemAddress(area=0x8A0E0001, sub_area=0x9F6)
addr.lid = [0x1]

temp_tag = tag_factory("DB1.Temperature", addr, Softdatatype.REAL)
# Returns a PlcTag with write_cls=ValueReal

# Read
result = read_tags(conn, [temp_tag])
if result == 0 and temp_tag.quality == Quality.GOOD:
    print(f"{temp_tag.name} = {temp_tag.value}")  # e.g. "DB1.Temperature = 72.5"

# Modify and write back
temp_tag.value = 85.0
result = write_tags(conn, [temp_tag])
if result == 0 and temp_tag.last_write_error == 0:
    print("Write successful")
```

### 8.5 Working with Special Data Types

```python
from datetime import datetime
from s7commplus.client_api.plc_tag import tag_factory, read_tags, write_tags
from s7commplus.protocol.constants import Softdatatype

# String tag
str_tag = tag_factory("DB1.ProductName", addr, Softdatatype.STRING)
read_tags(conn, [str_tag])
print(str_tag.value)  # e.g. "Widget-A"
str_tag.value = "Widget-B"
write_tags(conn, [str_tag])

# Date tag — value is a datetime object
date_tag = tag_factory("DB1.ProductionDate", addr, Softdatatype.DATE)
read_tags(conn, [date_tag])
print(date_tag.value)  # e.g. datetime(2024, 6, 15, 0, 0)
date_tag.value = datetime(2025, 1, 1)
write_tags(conn, [date_tag])

# DTL (Date and Time Long) — 12-byte struct with nanosecond precision
dtl_tag = tag_factory("DB1.Timestamp", addr, Softdatatype.DTL)
read_tags(conn, [dtl_tag])
print(dtl_tag.value)        # datetime object
print(dtl_tag.nanosecond)   # nanosecond component (0–999999999)

# S5TIME — BCD-encoded with time base
s5t_tag = tag_factory("DB1.Delay", addr, Softdatatype.S5TIME)
read_tags(conn, [s5t_tag])
print(f"Time value: {s5t_tag.time_value}, base: {s5t_tag.time_base}")
print(f"Milliseconds: {s5t_tag.milliseconds}")  # computed from value × base

# Bool tag
bool_tag = tag_factory("DB1.MotorOn", addr, Softdatatype.BOOL)
read_tags(conn, [bool_tag])
if bool_tag.value:
    print("Motor is running")
```

### 8.6 Batch Read/Write

```python
from s7commplus.client_api.plc_tag import tag_factory, read_tags, write_tags, Quality

# Create multiple tags
tags = [
    tag_factory("DB1.Temp", addr1, Softdatatype.REAL),
    tag_factory("DB1.Pressure", addr2, Softdatatype.REAL),
    tag_factory("DB1.Active", addr3, Softdatatype.BOOL),
    tag_factory("DB1.Counter", addr4, Softdatatype.DINT),
    tag_factory("DB1.Name", addr5, Softdatatype.STRING),
]

# Batch read — automatically chunked by comm_resources.tags_per_read_max
result = read_tags(conn, tags)
if result == 0:
    for tag in tags:
        status = "OK" if tag.quality == Quality.GOOD else "ERROR"
        print(f"  {tag.name} = {tag.value}  [{status}]")

# Modify values
tags[0].value = 99.5    # Temperature
tags[2].value = False    # Active

# Batch write — automatically chunked by comm_resources.tags_per_write_max
result = write_tags(conn, tags)
```

### 8.7 Browsing PLC Variables

```python
from s7commplus.client_api.browser import Browser
from s7commplus.client_api.var_info import NodeType
from s7commplus.client_api.plc_tag import tag_factory

# After connecting, build the browser (using objects from ExploreRequest/Response)
browser = Browser()

# Add data blocks discovered via Explore
browser.add_block_node(NodeType.ROOT, "MyDB", access_id=0x8A0E0001, ti_rel_id=rel_id)

# Set type-info objects from TypeInfoContainer explore
browser.set_type_info_objects(type_info_objects)

# Build and flatten
browser.build_tree()
browser.build_flat_list()

# Iterate all discovered variables
for info in browser.var_info_list:
    print(f"{info.name:40s}  sdt={info.softdatatype:3d}  "
          f"access={info.access_sequence}  "
          f"opt={info.opt_address}:{info.opt_bitoffset}")

# Create PlcTag instances from VarInfo
tags = []
for info in browser.var_info_list:
    addr = ItemAddress.from_access_sequence(info.access_sequence)
    tag = tag_factory(info.name, addr, info.softdatatype)
    if tag is not None:
        tags.append(tag)

# Now read all tags
result = read_tags(conn, tags)
```

### 8.8 Setting CPU Operating State

```python
# RUN = 1, STOP = 2 (defined in Ids)
err = conn.set_plc_operating_state(1)  # Set to RUN
if err != 0:
    print(f"Failed to set operating state: {err}")
```

### 8.9 TLS Key Logging for Wireshark

```python
# Option 1: Explicit file path
conn.connect("192.168.1.30", keylog_file="/tmp/keys.log")

# Option 2: Environment variable (standard NSS/OpenSSL convention)
import os
os.environ["SSLKEYLOGFILE"] = "/tmp/keys.log"
conn.connect("192.168.1.30")

# Then in Wireshark:
#   Edit → Preferences → Protocols → TLS
#   → (Pre)-Master-Secret log filename = /tmp/keys.log
```

---

## 9. Error Handling

All methods return integer error codes. `0` means success.

```python
from s7commplus.protocol.errors import (
    ERR_TCP_CONNECTION_FAILED,    # TCP connect failed
    ERR_TCP_DATA_SEND,            # TCP send failed
    ERR_TCP_DATA_RECEIVE,         # TCP receive timeout or failure
    ERR_TCP_NOT_CONNECTED,        # Socket not connected
    ERR_ISO_CONNECT,              # COTP handshake failed
    ERR_ISO_INVALID_PDU,          # Malformed PDU received
    ERR_OPENSSL,                  # TLS error
    ERR_CLI_ACCESS_DENIED,        # Authentication failed
    ERR_CLI_FIRMWARE_NOT_SUPPORTED,  # Unsupported firmware version
    ERR_CLI_DEVICE_NOT_SUPPORTED,    # Unsupported device type
)

# PlcTag quality codes follow OPC DA:
from s7commplus.client_api.plc_tag import Quality
Quality.GOOD                 # 0xC0 — successful read
Quality.BAD                  # 0x00 — read failed
Quality.UNCERTAIN            # 0x40 — value may be stale
Quality.WAITING_FOR_INITIAL_DATA  # 0x20 — never been read
```

---

## 10. C# to Python Mapping

| C# Class / File | Python Module | Lines (C# → Py) | Notes |
|---|---|---|---|
| `MsgSocket.cs` | `transport/tcp_socket.py` | 211 → 203 | Nearly 1:1 |
| `S7Client.cs` | `transport/client.py` | 712 → 321 | ssl.MemoryBIO replaces OpenSSL P/Invoke |
| `OpenSSLConnector.cs + Native.cs` | `transport/tls.py` | 706 → 225 | 700+ lines of P/Invoke → 225 lines |
| `S7p.cs` | `protocol/s7p.py` | 768 → 454 | Python int simplifies VLQ |
| `PValue.cs` | `protocol/values.py` | 3,294 → 775 | Registry pattern collapses repetition |
| `PObject.cs + POffsetInfoType.cs + PVartypeList.cs + PVarnameList.cs` | `protocol/pobject.py` | 1,226 → 576 | Merged into one module |
| `6 constant files` | `protocol/constants.py` | 577 → 418 | Merged into one module |
| `S7Consts.cs` | `protocol/errors.py` | 102 → 178 | Added Python exceptions |
| `12 message files` | `messages/*.py` | 1,890 → 937 | ~75 lines per request/response pair |
| `Browser.cs` | `client_api/browser.py + var_info.py` | 701 → 444 | Split data structures out |
| `PlcTag.cs + PlcTags.cs + PlcTagQC.cs` | `client_api/plc_tag.py` | 2,733 → 574 | 40+ classes → 13 + data-driven map |
| `CommRessources.cs` | `client_api/comm_resources.py` | 184 → 95 | Nearly 1:1 |
| `Legitimation/ (4 files)` | `auth/legitimation.py` | 437 → 372 | hashlib + cryptography lib |
| `S7CommPlusConnection.cs` | `connection.py` | 1,434 → 624 | Orchestrator |
| **TOTAL** | | **~14,500 → 6,484** | **55% reduction** |
