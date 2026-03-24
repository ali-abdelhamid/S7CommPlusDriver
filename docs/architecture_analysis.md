# S7CommPlusDriver — Architecture Analysis & Python Porting Plan

**Source**: github.com/thomas-v2/S7CommPlusDriver (C#, 100%, LGPL-3.0)
**Total**: ~14,500 lines of C# across 60 files
**Goal**: Port to a Python library for reading/writing symbolic tags on S7-1200/1500 PLCs via S7CommPlus over TLS

---

## 1. Repository Structure at a Glance

```
S7CommPlusDriver/src/S7CommPlusDriver/
├── S7CommPlusConnection.cs          1,434 lines  ← ORCHESTRATOR (partial class spanning Legitimation/)
├── Net/                                          ← TRANSPORT LAYER
│   ├── S7Client.cs                    712 lines  ← TCP + COTP + TLS activation
│   ├── MsgSocket.cs                   211 lines  ← Raw TCP socket wrapper
│   └── S7Consts.cs                    102 lines  ← Error codes and param constants
├── OpenSSL/                                      ← TLS LAYER
│   ├── Native.cs                      346 lines  ← P/Invoke bindings to libssl/libcrypto
│   └── OpenSSLConnector.cs            360 lines  ← BIO-based TLS read/write pump
├── Core/                                         ← PROTOCOL SERIALIZATION
│   ├── S7p.cs                         768 lines  ← VLQ encoding/decoding + object deserialization
│   ├── PValue.cs                    3,294 lines  ← 50+ value type classes (Bool, Int, String, Struct...)
│   ├── PObject.cs                     174 lines  ← Protocol object (attributes, relations, children)
│   ├── POffsetInfoType.cs             779 lines  ← Offset/addressing metadata for variable types
│   ├── PVartypeList.cs                203 lines  ← Variable type list deserialization
│   ├── PVarnameList.cs                 71 lines  ← Variable name list deserialization
│   ├── BlobDecompressor.cs          1,808 lines  ← zlib decompression for comment blobs
│   ├── Softdatatype.cs                293 lines  ← PLC datatype enum (Bool, Int, Real, String...)
│   ├── Datatype.cs                     46 lines  ← Wire-level datatype IDs
│   ├── Ids.cs                         141 lines  ← All known protocol constants (RIDs, LIDs, class IDs)
│   ├── Functioncode.cs                 41 lines  ← Function codes (Explore, GetMultiVars, SetMultiVars...)
│   ├── Opcode.cs                       25 lines  ← Request/Response/Notification opcodes
│   ├── ProtocolVersion.cs              31 lines  ← V1, V2, V3, SystemEvent version bytes
│   ├── ElementID.cs                    29 lines  ← Start/End object markers, Attribute/Relation tags
│   ├── IS7pRequest.cs                  57 lines  ← Request interface
│   ├── IS7pResponse.cs                 49 lines  ← Response interface
│   ├── IS7pSerialize.cs                22 lines  ← Serialize interface
│   ├── Utils.cs                       157 lines  ← Hex dump, byte utilities
│   ├── CommRessources.cs              184 lines  ← Reads PLC system limits (max tags per read/write)
│   ├── SystemEvent.cs                 154 lines  ← Protocol error / system event handling
│   ├── Notification.cs                223 lines  ← Subscription notification deserialization
│   ├── ExploreRequest.cs              125 lines  ← Explore (browse) request serialization
│   ├── ExploreResponse.cs             112 lines  ← Explore response deserialization
│   ├── GetMultiVariablesRequest.cs    111 lines  ← Batch read request
│   ├── GetMultiVariablesResponse.cs   140 lines  ← Batch read response
│   ├── SetMultiVariablesRequest.cs    187 lines  ← Batch write request
│   ├── SetMultiVariablesResponse.cs   116 lines  ← Batch write response
│   ├── SetVariableRequest.cs          101 lines  ← Single variable write request
│   ├── SetVariableResponse.cs          95 lines  ← Single variable write response
│   ├── GetVarSubstreamedRequest.cs    100 lines  ← Substreamed read (used for auth/system queries)
│   ├── GetVarSubstreamedResponse.cs   101 lines  ← Substreamed read response
│   ├── CreateObjectRequest.cs         117 lines  ← Session creation request
│   ├── CreateObjectResponse.cs        110 lines  ← Session creation response
│   ├── DeleteObjectRequest.cs          85 lines  ← Session deletion request
│   ├── DeleteObjectResponse.cs        106 lines  ← Session deletion response
│   └── InitSslRequest/Response.cs     172 lines  ← SSL initiation handshake
├── ClientApi/                                    ← HIGH-LEVEL API
│   ├── Browser.cs                     701 lines  ← Object tree exploration, VarInfo tree builder
│   ├── PlcTag.cs                    2,412 lines  ← 40+ PlcTag subclasses (type conversion layer)
│   ├── PlcTags.cs                     279 lines  ← ReadTags/WriteTags extension + TagFactory
│   ├── PlcTagQC.cs                     42 lines  ← Quality code wrapper
│   └── ItemAddress.cs                 124 lines  ← Symbolic address builder (AccessArea.LID.LID...)
├── Legitimation/                                 ← AUTHENTICATION
│   ├── Legitimation.cs                351 lines  ← Password challenge/response (legacy + new)
│   ├── LegitimationCrypto.cs           56 lines  ← AES-CBC encrypt, SHA256
│   ├── AccessLevel.cs                  16 lines  ← Access level constants
│   └── LegitimationType.cs            14 lines  ← Legacy vs New login type
├── Subscriptions/                                ← CHANGE NOTIFICATIONS (optional)
│   └── Subscription.cs                234 lines  ← Create/delete/handle subscriptions
└── Alarming/                                     ← ALARM HANDLING (optional)
    ├── BrowseAlarms.cs                456 lines
    └── ... (6 more files)             ~700 lines
```

---

## 2. Dependency Map — What Calls What

```
User Code (DriverTest/Program.cs)
 │
 ▼
S7CommPlusConnection                          ← THE ORCHESTRATOR
 │  Owns: S7Client, CommRessources, Browser
 │  State: SessionId, SequenceNumber, IntegrityId counters
 │
 ├──▶ S7Client (Net/)                         ← TRANSPORT
 │    │  Owns: MsgSocket, OpenSSLConnector
 │    │  Methods: Connect(), Send(), SslActivate(), Disconnect()
 │    │
 │    ├──▶ MsgSocket                          ← RAW TCP
 │    │    Uses: System.Net.Sockets.Socket
 │    │    Methods: Connect(), Send(), Receive(), Close()
 │    │
 │    └──▶ OpenSSLConnector (OpenSSL/)        ← TLS
 │         │  Uses: Native.cs (P/Invoke → libssl-3.dll / libcrypto-3.dll)
 │         │  Pattern: BIO memory buffers, no direct socket access
 │         │  Key: S7Client implements IConnectorCallback:
 │         │       WriteData() → wraps in TPKT/COTP → sends on socket
 │         │       OnDataAvailable() → fires S7CommPlusConnection.OnDataReceived()
 │         │
 │         └──▶ Native.cs
 │              P/Invoke: SSL_new, SSL_read, SSL_write, BIO_new, BIO_write,
 │              BIO_read, SSL_CTX_new, SSL_set_bio, SSL_export_keying_material
 │
 ├──▶ Core/ Request/Response Classes          ← PROTOCOL MESSAGES
 │    │  All implement IS7pRequest or IS7pResponse
 │    │  All use S7p.Encode*/Decode* for serialization
 │    │
 │    ├── InitSslRequest/Response             ← Step 1: Pre-TLS SSL init
 │    ├── CreateObjectRequest/Response        ← Step 3: Create session
 │    ├── SetMultiVariablesRequest/Response   ← Step 4: Session setup & writes
 │    ├── GetMultiVariablesRequest/Response   ← Batch reads
 │    ├── SetVariableRequest/Response         ← Single writes
 │    ├── GetVarSubstreamedRequest/Response   ← System queries & auth
 │    ├── ExploreRequest/Response             ← Browse/discover objects
 │    ├── CreateObject/DeleteObject Req/Res   ← Object lifecycle
 │    └── Notification                        ← Subscription push data
 │
 ├──▶ S7p (Core/)                             ← SERIALIZATION ENGINE
 │    Static methods:
 │    ├── EncodeByte/UInt16/UInt32/UInt64     (big-endian fixed)
 │    ├── EncodeUInt32Vlq / DecodeUInt32Vlq   (variable-length quantity)
 │    ├── EncodeInt32Vlq / DecodeInt32Vlq     (signed VLQ with sign bit)
 │    ├── EncodeUInt64Vlq / DecodeUInt64Vlq   (64-bit VLQ)
 │    ├── DecodeObject / DecodeObjectList     (recursive object tree parser)
 │    └── EncodeObjectQualifier              (standard object qualifier block)
 │
 ├──▶ PValue hierarchy (Core/)                ← VALUE TYPE SYSTEM
 │    Abstract base: PValue (flags + datatype tag + Serialize/Deserialize)
 │    50+ concrete types:
 │    ├── Scalars: ValueBool, ValueByte, ValueUSInt, ValueUInt, ValueUDInt,
 │    │            ValueULInt, ValueSInt, ValueInt, ValueDInt, ValueLInt,
 │    │            ValueWord, ValueDWord, ValueLWord, ValueReal, ValueLReal,
 │    │            ValueTimestamp, ValueTimespan, ValueRID, ValueAID,
 │    │            ValueBlob, ValueWString, ValueNull
 │    ├── Arrays:  Value{Type}Array for each scalar
 │    ├── Sparse:  ValueUDIntSparseArray, ValueDIntSparseArray,
 │    │            ValueBlobSparseArray, ValueWStringSparseArray
 │    └── Struct:  ValueStruct (recursive, keyed by UInt32 element IDs)
 │    
 │    Deserialization: PValue.Deserialize(stream) reads flags+datatype tag,
 │    dispatches to correct subclass via giant switch statement.
 │
 ├──▶ PObject (Core/)                         ← PROTOCOL OBJECT MODEL
 │    Fields: RelationId, ClassId, ClassFlags, AttributeId
 │    Contains: Dict<uint, PValue> Attributes
 │              Dict<Tuple<uint,uint>, PObject> Objects (children)
 │              Dict<uint, uint> Relations
 │              PVartypeList, PVarnameList
 │
 ├──▶ Browser (ClientApi/)                    ← SYMBOL TREE BUILDER
 │    1. Receives block info from S7CommPlusConnection.Browse()
 │    2. Receives TypeInfoContainer objects
 │    3. BuildTree(): matches blocks to type info via RelationIds
 │    4. BuildFlatList(): walks tree → produces List<VarInfo>
 │    Output: VarInfo { Name, AccessSequence, Softdatatype, OptAddress, ... }
 │
 ├──▶ PlcTag / PlcTags (ClientApi/)           ← USER-FACING TYPE LAYER
 │    PlcTag base: Name, Address (ItemAddress), Datatype, Value, Quality
 │    40+ subclasses: PlcTagBool, PlcTagInt, PlcTagReal, PlcTagString, ...
 │    Each overrides: ProcessReadResult(value, error), GetWriteValue()
 │    PlcTags.TagFactory(): softdatatype → correct PlcTag subclass
 │    PlcTags.ReadTags(): batch read via connection.ReadValues()
 │    PlcTags.WriteTags(): batch write via connection.WriteValues()
 │
 └──▶ Legitimation (Legitimation/)            ← AUTH (partial class of S7CommPlusConnection)
      Two paths based on firmware version:
      ├── legitimateLegacy(): SHA1(password) XOR challenge → SetVariable
      └── legitimateNew(): OMS exporter secret → SHA256 key rolling →
                           AES-CBC encrypt(payload, key, iv=challenge[:16]) → SetVariable
```

---

## 3. The Connection Lifecycle (Data Flow)

### 3.1 Connect Sequence

```
conn.Connect("192.168.1.30", password, username)
│
├─ Step 1: S7Client.Connect()
│  ├─ TCPConnect() → raw TCP to port 102
│  └─ ISOConnect() → COTP CR/CC exchange (Remote TSAP = "SIMATIC-ROOT-HMI")
│     └─ Starts background RunThread (continuously reads TPKT packets)
│
├─ Step 2: InitSslRequest/Response (unencrypted, ProtocolVersion.V1)
│  └─ Tells PLC: "I want to start TLS"
│
├─ Step 3: S7Client.SslActivate()
│  ├─ OPENSSL_init_ssl()
│  ├─ SSL_CTX_new(TLS_client_method())
│  ├─ Force TLS 1.3: SSL_CTX_ctrl(SET_MIN_PROTO_VERSION, TLS1_3_VERSION)
│  ├─ Set ciphersuites: TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
│  ├─ Create OpenSSLConnector with BIO memory buffers
│  ├─ SSL_set_connect_state() → initiates ClientHello
│  └─ Set keylog callback (for Wireshark debugging)
│  ══════════ ALL TRAFFIC FROM HERE IS TLS-ENCRYPTED ══════════
│
├─ Step 4: CreateObjectRequest/Response (ProtocolVersion.V1, encrypted)
│  ├─ Creates a server session → PLC returns SessionId (+ SessionId2)
│  └─ Extracts ServerSessionVersion struct (contains firmware info)
│
├─ Step 5: SetMultiVariablesRequest/Response (ProtocolVersion.V2)
│  └─ Session setup data (echoes back server session parameters)
│
├─ Step 6: CommRessources.ReadMax()
│  └─ Reads SystemLimits: max tags per read, max tags per write,
│     max subscriptions, etc. (via GetMultiVariables)
│
└─ Step 7: Legitimation (password handling)
   ├─ Parse firmware version from ServerSession PAOM string
   ├─ Read EffectiveProtectionLevel (via GetVarSubstreamed)
   ├─ If password needed:
   │  ├─ Legacy (FW < 3.1): SHA1(pw) XOR 20-byte challenge
   │  └─ New (FW >= 3.1):
   │     ├─ Get OMS exporter secret: SSL_export_keying_material("EXPERIMENTAL_OMS")
   │     ├─ Key = SHA256(omsSecret), IV = challenge[0:16]
   │     └─ AES-CBC encrypt serialized legitimation payload
   └─ Send response via SetVariable → verify ReturnValue >= 0
```

### 3.2 Browse Sequence (Discover All Tags)

```
conn.Browse(out varInfoList)
│
├─ Phase 1: Explore the PLC Program root
│  ExploreRequest { ExploreId = NativeObjects_thePLCProgram_Rid (3),
│                   ChildsRecursive = 1,
│                   AddressList = [ObjectVariableTypeName, Block_BlockNumber, ASObjectES_Comment] }
│  → Returns list of PObjects, each representing a DB, FC, FB, etc.
│  → Filter by ClassId == DB_Class_Rid → extract db_name, db_number, db_block_relid
│
├─ Phase 2: Resolve Type-Info RIDs for each data block
│  For each DB, read LID=1 from (db_block_relid, DB_ValueActual)
│  via GetMultiVariables → returns ValueRID = the Type-Info RelId
│  This indirection is needed because instance DBs (e.g., TON timer)
│  store their type info under a different RID than the DB itself.
│
├─ Phase 3: Add I/Q/M/Timer/Counter areas manually
│  These aren't discovered via Explore; they're hard-coded:
│  IArea=0x90010000, QArea=0x90020000, MArea=0x90030000, etc.
│
├─ Phase 4: Explore the TypeInfoContainer (one big PDU)
│  ExploreRequest { ExploreId = ObjectOMSTypeInfoContainer (537),
│                   ChildsRecursive = 1 }
│  → Returns the ENTIRE type information tree in potentially
│    hundreds of fragmented PDUs (reassembled by OnDataReceived)
│
└─ Phase 5: Browser builds the variable tree
   browser.SetTypeInfoContainerObjects(objs)
   browser.BuildTree()
     → Matches each DB's ti_relid to a TypeInfo PObject
     → Walks PVartypeList + PVarnameList to build Node tree
     → Handles arrays (1D, multi-dim), structs, nested types
   browser.BuildFlatList()
     → Walks tree depth-first → produces flat List<VarInfo>
        VarInfo { Name="MyDB.Temperature", AccessSequence="8A0E0001.F",
                  Softdatatype=8 (Real), OptAddress=4, NonOptAddress=12 }
```

### 3.3 Read/Write Sequence

```
conn.ReadValues(addressList, out values, out errors)
│
├─ Splits addresses into chunks (max = CommRessources.TagsPerReadRequestMax)
├─ For each chunk:
│  ├─ Build GetMultiVariablesRequest with ItemAddress list
│  │   ItemAddress = { SymbolCrc, AccessArea (e.g., 0x8A0E0001 for DB1),
│  │                   AccessSubArea (DB_ValueActual=2550),
│  │                   LID chain (e.g., [0xF] for variable at LID 15) }
│  ├─ Serialize → S7CommPlus PDU → fragment if > MaxSize
│  ├─ Send through TLS tunnel
│  ├─ Wait for response (threaded receive via RunThread)
│  └─ Deserialize GetMultiVariablesResponse → values + error codes
└─ Merge chunk results

conn.WriteValues(addressList, valuesList, out errors)
│  Same pattern but uses SetMultiVariablesRequest
│  Values are PValue instances (e.g., ValueInt(42), ValueReal(3.14))
```

### 3.4 Symbol-Based Tag Access (Higher-Level API)

```
PlcTag tag = conn.getPlcTagBySymbol("MyDB.Temperature")
│
├─ Lazy-loads datablock list if not cached (GetListOfDatablocks)
├─ Parses symbol level by level: "MyDB" → "Temperature"
├─ Finds DB by first level name
├─ browsePlcTagBySymbol(ti_relid, symbol, varInfo):
│  ├─ getTypeInfoByRelId(ti_relid) → PObject with VarnameList
│  ├─ Find "Temperature" in VarnameList → get index
│  ├─ Look up VartypeList[index] → PVartypeListElement
│  │   Contains: LID, Softdatatype, OffsetInfoType
│  ├─ Build AccessSequence string: "8A0E0001.F"
│  ├─ If struct → recurse into child type via RelationId
│  ├─ If array → calculate index offset
│  └─ Return PlcTags.TagFactory(name, address, softdatatype)
│     → PlcTagReal(name, address, 8)
│
├─ conn.ReadTags([tag])
│  → conn.ReadValues([tag.Address]) → tag.ProcessReadResult(value)
│  → tag.Value now contains the float value
│
└─ tag.Value = 99.5f; conn.WriteTags([tag])
   → tag.GetWriteValue() → ValueReal(99.5)
   → conn.WriteValues([tag.Address], [ValueReal(99.5)])
```

---

## 4. Key Engineering Decisions for the Python Port

### 4.1 The TLS Layer is the Easiest Part

The C# driver's most platform-specific code (700+ lines of OpenSSL P/Invoke and BIO buffer management) is replaced entirely by Python's `ssl` module:

| C# (OpenSSL P/Invoke)                    | Python Equivalent                         |
|-------------------------------------------|-------------------------------------------|
| `Native.OPENSSL_init_ssl()`               | Automatic                                 |
| `Native.SSL_CTX_new(TLS_client_method())` | `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` |
| `SSL_CTX_ctrl(SET_MIN_PROTO_VERSION, TLS1_3_VERSION)` | `ctx.minimum_version = ssl.TLSVersion.TLSv1_3` |
| `SSL_CTX_set_ciphersuites(...)`           | `ctx.set_ciphers(...)` |
| `OpenSSLConnector` + BIO buffers          | `ctx.wrap_socket(sock)` — one line        |
| `SSL_export_keying_material("EXPERIMENTAL_OMS")` | `ssl_sock.export_keying_material("EXPERIMENTAL_OMS", 32)` |
| `SSL_CTX_set_keylog_callback()`           | `ctx.keylog_filename = "keys.log"`        |

The BIO memory buffer pattern used in C# (where OpenSSL doesn't touch the socket directly but instead reads/writes through in-memory BIOs, and the driver manually ferries encrypted bytes to/from the COTP layer) exists because TLS runs *inside* COTP frames, not directly on the TCP socket. In Python, you'll need the same indirection — you can't just `ssl.wrap_socket()` the raw TCP socket because TLS records need to be encapsulated in TPKT/COTP data frames.

**Python approach**: Use `ssl.MemoryBIO` (available since Python 3.6). Create an `ssl.SSLObject` with two `MemoryBIO` instances (incoming and outgoing), then manually shuttle bytes between the BIOs and your COTP framing layer. This is the direct Python equivalent of the C# BIO pattern, without needing any C bindings.

### 4.2 The VLQ Encoding is Critical Path

The S7CommPlus protocol uses Variable Length Quantity encoding pervasively — every ID, every count, every address field uses VLQ. The `S7p` class has both unsigned and signed variants for 32-bit and 64-bit values. The signed variant uses a sign bit in the first byte's bit 6 position with one's complement pre-loading — this is non-standard and must be ported exactly.

### 4.3 The PValue Type Hierarchy is the Largest Single Port

At 3,294 lines, `PValue.cs` contains 50+ concrete value types. The good news: they're highly repetitive. Each follows the same pattern — a datatype tag, a Serialize method, a static Deserialize method, and a GetValue accessor. In Python, you can significantly compress this using `struct.pack`/`struct.unpack` and a registry/factory pattern instead of 50 separate classes.

### 4.4 The Browser Tree-Building Logic is the Most Complex

`Browser.cs` (701 lines) and the related `POffsetInfoType.cs` (779 lines) contain the trickiest logic: parsing the TypeInfoContainer response and matching type information to variable names, handling arrays, structs, nested types, and building the access sequence strings. This must be ported carefully with test vectors.

---

## 5. Proposed Python Module Layout

```
s7commplus/
├── __init__.py                      ← Public API: S7CommPlusConnection
├── connection.py                    ← Main orchestrator (from S7CommPlusConnection.cs)
│                                      Connect(), Disconnect(), Browse(),
│                                      ReadValues(), WriteValues(), getPlcTagBySymbol()
│
├── transport/
│   ├── __init__.py
│   ├── tcp_socket.py                ← MsgSocket.cs → simple socket wrapper
│   ├── cotp.py                      ← COTP/TPKT framing (from S7Client.cs ISO parts)
│   │                                  ISOConnect(), SendIsoPacket(), RecvIsoPacket()
│   ├── tls.py                       ← TLS layer using ssl.MemoryBIO + ssl.SSLObject
│   │                                  Replaces: Native.cs + OpenSSLConnector.cs (700+ lines → ~100 lines)
│   │                                  Key: export_keying_material() for OMS secret
│   └── client.py                    ← S7Client.cs orchestrator: TCP→COTP→TLS→callback
│                                      Background receive thread, Send/Receive, SslActivate()
│
├── protocol/
│   ├── __init__.py
│   ├── s7p.py                       ← S7p.cs: VLQ encode/decode, big-endian encode/decode,
│   │                                  DecodeObject, DecodeObjectList, EncodeObjectQualifier
│   ├── values.py                    ← PValue.cs: The type system. Use a registry pattern:
│   │                                  @register_type(datatype_id) decorator per type,
│   │                                  PValue.deserialize() dispatches via registry.
│   │                                  Scalar types use struct.pack/unpack.
│   │                                  ValueStruct handled recursively.
│   ├── pobject.py                   ← PObject.cs: Protocol object with attributes/children
│   ├── offset_info.py               ← POffsetInfoType.cs: Offset and addressing metadata
│   ├── vartype_list.py              ← PVartypeList.cs + PVarnameList.cs
│   ├── constants.py                 ← Merge of: Ids.cs, Functioncode.cs, Opcode.cs,
│   │                                  Datatype.cs, ElementID.cs, ProtocolVersion.cs, Softdatatype.cs
│   │                                  All as Python constants/enums
│   ├── errors.py                    ← S7Consts.cs error codes + exception classes
│   └── utils.py                     ← Utils.cs: hex dump, byte manipulation
│
├── messages/
│   ├── __init__.py
│   ├── base.py                      ← IS7pRequest/IS7pResponse as Python ABCs
│   ├── init_ssl.py                  ← InitSslRequest + InitSslResponse
│   ├── create_object.py             ← CreateObjectRequest + CreateObjectResponse
│   ├── delete_object.py             ← DeleteObjectRequest + DeleteObjectResponse
│   ├── explore.py                   ← ExploreRequest + ExploreResponse
│   ├── get_multi_variables.py       ← GetMultiVariablesRequest + GetMultiVariablesResponse
│   ├── set_multi_variables.py       ← SetMultiVariablesRequest + SetMultiVariablesResponse
│   ├── set_variable.py              ← SetVariableRequest + SetVariableResponse
│   ├── get_var_substreamed.py       ← GetVarSubstreamedRequest + GetVarSubstreamedResponse
│   ├── notification.py              ← Notification deserialization
│   └── system_event.py              ← SystemEvent deserialization
│
├── client_api/
│   ├── __init__.py
│   ├── browser.py                   ← Browser.cs: Tree building, flat list generation
│   ├── item_address.py              ← ItemAddress.cs: Symbolic address construction
│   ├── plc_tag.py                   ← PlcTag.cs + PlcTags.cs: Pythonic tag interface
│   │                                  Can flatten to far fewer classes using generics/dataclasses
│   ├── var_info.py                  ← VarInfo, BrowseData, DatablockInfo structs
│   └── comm_resources.py            ← CommRessources.cs: System limits
│
├── auth/
│   ├── __init__.py
│   └── legitimation.py              ← Legitimation.cs + LegitimationCrypto.cs
│                                      Uses: hashlib.sha1, hashlib.sha256
│                                      Uses: cryptography.hazmat AES-CBC
│                                      Firmware version parsing, challenge/response
│
├── subscriptions/                    ← OPTIONAL (phase 2)
│   ├── __init__.py
│   └── subscription.py              ← Subscription.cs
│
└── alarming/                         ← OPTIONAL (phase 3)
    ├── __init__.py
    └── ...
```

### Estimated Line Counts per Module

| Python Module | C# Source Lines | Est. Python Lines | Notes |
|---|---|---|---|
| `transport/` | 1,629 | ~400 | ssl.MemoryBIO eliminates 700 lines of OpenSSL interop |
| `protocol/s7p.py` | 768 | ~350 | Direct port, Python int handling simplifies some VLQ |
| `protocol/values.py` | 3,294 | ~800 | Registry pattern + struct.pack collapses repetition |
| `protocol/pobject.py` | 174 | ~120 | Nearly 1:1 |
| `protocol/offset_info.py` | 779 | ~400 | Complex but mechanical |
| `protocol/constants.py` | 577 (6 files) | ~300 | Merge into one module with enums |
| `messages/` | 1,890 (12 files) | ~900 | Each request/response pair ~75 lines |
| `client_api/browser.py` | 701 | ~500 | Most complex logic; test carefully |
| `client_api/plc_tag.py` | 2,691 (2 files) | ~600 | Dataclasses + dict-based factory |
| `client_api/` (rest) | 350 | ~200 | |
| `auth/legitimation.py` | 437 | ~200 | hashlib + cryptography lib |
| `connection.py` | 1,434 | ~600 | Orchestrator |
| **TOTAL (core)** | **~14,500** | **~5,400** | **~63% reduction** |

---

## 6. Porting Priority Order

### Phase A — Transport (get bytes flowing)
Port: `transport/`, `protocol/s7p.py`, `protocol/constants.py`, `protocol/errors.py`
Test: Connect to PLC, complete COTP handshake, activate TLS, verify with Wireshark

### Phase B — Protocol core (serialize/deserialize messages)
Port: `protocol/values.py`, `protocol/pobject.py`, `messages/`
Test: Send InitSslRequest, CreateObject, receive responses, verify field values

### Phase C — Connection lifecycle
Port: `connection.py`, `auth/legitimation.py`, `client_api/comm_resources.py`
Test: Full Connect() → authenticated session, read system limits

### Phase D — Browse and tag access
Port: `client_api/browser.py`, `protocol/offset_info.py`, `protocol/vartype_list.py`
Test: Browse() → get full variable list, compare to TIA Portal project

### Phase E — Read/Write API
Port: `client_api/plc_tag.py`, `client_api/item_address.py`
Test: Read all variables, write test values, verify round-trip

### Phase F (optional) — Subscriptions and alarming
Port: `subscriptions/`, `alarming/`
