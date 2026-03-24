"""
Protocol constants for S7CommPlus.

Merged from C# sources: Ids.cs, Functioncode.cs, Opcode.cs, Datatype.cs,
ElementID.cs, ProtocolVersion.cs, Softdatatype.cs.
"""

from enum import IntEnum


# ---------------------------------------------------------------------------
# Protocol Versions  (ProtocolVersion.cs)
# ---------------------------------------------------------------------------

class ProtocolVersion:
    V1 = 0x01
    V2 = 0x02
    V3 = 0x03
    SYSTEM_EVENT = 0xFE


# ---------------------------------------------------------------------------
# Opcodes  (Opcode.cs)
# ---------------------------------------------------------------------------

class Opcode:
    REQUEST = 0x31
    RESPONSE = 0x32
    NOTIFICATION = 0x33
    RESPONSE2 = 0x02


# ---------------------------------------------------------------------------
# Function Codes  (Functioncode.cs)
# ---------------------------------------------------------------------------

class FunctionCode:
    ERROR = 0x04B1
    EXPLORE = 0x04BB
    CREATE_OBJECT = 0x04CA
    DELETE_OBJECT = 0x04D4
    SET_VARIABLE = 0x04F2
    GET_VARIABLE = 0x04FC  # only in old 1200 FW
    ADD_LINK = 0x0506
    REMOVE_LINK = 0x051A
    GET_LINK = 0x0524
    SET_MULTI_VARIABLES = 0x0542
    GET_MULTI_VARIABLES = 0x054C
    BEGIN_SEQUENCE = 0x0556
    END_SEQUENCE = 0x0560
    INVOKE = 0x056B
    SET_VAR_SUB_STREAMED = 0x057C
    GET_VAR_SUB_STREAMED = 0x0586
    GET_VARIABLES_ADDRESS = 0x0590
    ABORT = 0x059A
    ERROR2 = 0x05A9
    INIT_SSL = 0x05B3


# ---------------------------------------------------------------------------
# Wire-Level Datatype IDs  (Datatype.cs)
# ---------------------------------------------------------------------------

class Datatype:
    NULL = 0x00
    BOOL = 0x01
    USINT = 0x02
    UINT = 0x03
    UDINT = 0x04
    ULINT = 0x05
    SINT = 0x06
    INT = 0x07
    DINT = 0x08
    LINT = 0x09
    BYTE = 0x0A
    WORD = 0x0B
    DWORD = 0x0C
    LWORD = 0x0D
    REAL = 0x0E
    LREAL = 0x0F
    TIMESTAMP = 0x10
    TIMESPAN = 0x11
    RID = 0x12
    AID = 0x13
    BLOB = 0x14
    WSTRING = 0x15
    VARIANT = 0x16
    STRUCT = 0x17
    S7STRING = 0x19


# ---------------------------------------------------------------------------
# Element IDs — Protocol Object Markers  (ElementID.cs)
# ---------------------------------------------------------------------------

class ElementID:
    START_OF_OBJECT = 0xA1
    TERMINATING_OBJECT = 0xA2
    ATTRIBUTE = 0xA3
    RELATION = 0xA4
    START_OF_TAG_DESCRIPTION = 0xA7
    TERMINATING_TAG_DESCRIPTION = 0xA8
    VARTYPE_LIST = 0xAB
    VARNAME_LIST = 0xAC


# ---------------------------------------------------------------------------
# Protocol IDs  (Ids.cs)
# ---------------------------------------------------------------------------

class Ids:
    NONE = 0

    # Native objects
    NATIVE_OBJECTS_THE_PLC_PROGRAM_RID = 3
    NATIVE_OBJECTS_THE_ALARM_SUBSYSTEM_RID = 8
    NATIVE_OBJECTS_THE_CPU_EXEC_UNIT_RID = 52
    NATIVE_OBJECTS_THE_I_AREA_RID = 80
    NATIVE_OBJECTS_THE_Q_AREA_RID = 81
    NATIVE_OBJECTS_THE_M_AREA_RID = 82
    NATIVE_OBJECTS_THE_S7_COUNTERS_RID = 83
    NATIVE_OBJECTS_THE_S7_TIMERS_RID = 84

    # Object and class IDs
    OBJECT_ROOT = 201
    GET_NEW_RID_ON_SERVER = 211
    OBJECT_VARIABLE_TYPE_PARENT_OBJECT = 229
    OBJECT_VARIABLE_TYPE_NAME = 233
    CLASS_SUBSCRIPTIONS = 255
    CLASS_SERVER_SESSION_CONTAINER = 284
    OBJECT_SERVER_SESSION_CONTAINER = 285
    CLASS_SERVER_SESSION = 287
    OBJECT_NULL_SERVER_SESSION = 288

    # Server session
    SERVER_SESSION_CLIENT_RID = 300
    SERVER_SESSION_REQUEST = 303
    SERVER_SESSION_RESPONSE = 304
    SERVER_SESSION_VERSION = 306
    LID_SESSION_VERSION_SYSTEM_PAOM_STRING = 319

    # Type info
    CLASS_TYPE_INFO = 511
    CLASS_OMS_TYPE_INFO_CONTAINER = 534
    OBJECT_OMS_TYPE_INFO_CONTAINER = 537

    # Text library
    TEXT_LIBRARY_CLASS_RID = 606
    TEXT_LIBRARY_OFFSET_AREA = 608
    TEXT_LIBRARY_STRING_AREA = 609

    # Subscriptions
    CLASS_SUBSCRIPTION = 1001
    SUBSCRIPTION_MISSED_SENDINGS = 1002
    SUBSCRIPTION_SUBSYSTEM_ERROR = 1003
    SUBSCRIPTION_REFERENCE_TRIGGER_AND_TRANSMIT_MODE = 1005
    SYSTEM_LIMITS = 1037
    SUBSCRIPTION_ROUTE_MODE = 1040
    SUBSCRIPTION_ACTIVE = 1041
    SUBSCRIPTION_REFERENCE_LIST = 1048
    SUBSCRIPTION_CYCLE_TIME = 1049
    SUBSCRIPTION_DELAY_TIME = 1050
    SUBSCRIPTION_DISABLED = 1051
    SUBSCRIPTION_COUNT = 1052
    SUBSCRIPTION_CREDIT_LIMIT = 1053
    SUBSCRIPTION_TICKS = 1054
    FREE_ITEMS = 1081
    SUBSCRIPTION_FUNCTION_CLASS_ID = 1082

    # Filter
    FILTER = 1246
    FILTER_OPERATION = 1247
    ADDRESS_COUNT = 1249
    ADDRESS = 1250
    FILTER_VALUE = 1251

    # Object qualifier
    OBJECT_QUALIFIER = 1256
    PARENT_RID = 1257
    COMPOSITION_AID = 1258
    KEY_QUALIFIER = 1259

    # Type info
    TI_TCOM_SIZE = 1502

    # Protection
    EFFECTIVE_PROTECTION_LEVEL = 1842
    ACTIVE_PROTECTION_LEVEL = 1843
    LEGITIMATE = 1846

    # CPU
    CPU_EXEC_UNIT_OPERATING_STATE_REQ = 2167

    # PLC Program
    PLC_PROGRAM_CLASS_RID = 2520
    BLOCK_BLOCK_NUMBER = 2521
    DATA_INTERFACE_INTERFACE_DESCRIPTION = 2544
    DATA_INTERFACE_LINE_COMMENTS = 2546
    DB_VALUE_INITIAL = 2548
    DB_VALUE_ACTUAL = 2550
    DB_INITIAL_CHANGED = 2551
    DB_CLASS_RID = 2574

    # Alarm subscription
    ALARM_SUBSCRIPTION_REF_ALARM_DOMAIN = 2659
    ALARM_SUBSCRIPTION_REF_ITS_ALARM_SUBSYSTEM = 2660
    ALARM_SUBSCRIPTION_REF_CLASS_RID = 2662
    ALARM_SUBSYSTEM_ITS_UPDATE_RELEVANT_DAI = 2667

    # DAI
    DAI_CPU_ALARM_ID = 2670
    DAI_ALL_STATES_INFO = 2671
    DAI_ALARM_DOMAIN = 2672
    DAI_COMING = 2673
    DAI_GOING = 2677
    DAI_CLASS_RID = 2681
    DAI_ALARM_TEXTS_RID = 2715

    # Alarm CGS
    AS_CGS_ALL_STATES_INFO = 3474
    AS_CGS_TIMESTAMP = 3475
    AS_CGS_ASSOCIATED_VALUES = 3476
    AS_CGS_ACK_TIMESTAMP = 3646

    # Controller area
    CONTROLLER_AREA_VALUE_INITIAL = 3735
    CONTROLLER_AREA_VALUE_ACTUAL = 3736
    CONTROLLER_AREA_RUNTIME_MODIFIED = 3737

    # DAI extras
    DAI_MESSAGE_TYPE = 4079
    AS_OBJECT_ES_COMMENT = 4288
    ALARM_SUBSCRIPTION_REF_ALARM_DOMAIN2 = 7731
    DAI_HMI_INFO = 7813

    # Multiple STAI
    MULTIPLE_STAI_CLASS_RID = 7854
    MULTIPLE_STAI_STAIS = 7859
    DAI_SEQUENCE_COUNTER = 7917

    # Alarm text
    ALARM_SUBSCRIPTION_REF_ALARM_TEXT_LANGUAGES_RID = 8181
    ALARM_SUBSCRIPTION_REF_SEND_ALARM_TEXTS_RID = 8173

    # Return value
    RETURN_VALUE = 40305

    # Legitimation
    LID_LEGITIMATION_PAYLOAD_STRUCT = 40400
    LID_LEGITIMATION_PAYLOAD_TYPE = 40401
    LID_LEGITIMATION_PAYLOAD_USERNAME = 40402
    LID_LEGITIMATION_PAYLOAD_PASSWORD = 40403

    # Type-Info IDs (base + offset)
    TI_BOOL = 0x02000001
    TI_BYTE = 0x02000002
    TI_CHAR = 0x02000003
    TI_WORD = 0x02000004
    TI_INT = 0x02000005
    TI_DWORD = 0x02000006
    TI_DINT = 0x02000007
    TI_REAL = 0x02000008
    TI_STRING = 0x02000013
    TI_LREAL = 0x02000030
    TI_USINT = 0x02000034
    TI_UINT = 0x02000035
    TI_UDINT = 0x02000036
    TI_SINT = 0x02000037
    TI_WCHAR = 0x0200003D
    TI_WSTRING = 0x0200003E
    TI_STRING_START = 0x020A0000
    TI_STRING_END = 0x020AFFFF
    TI_WSTRING_START = 0x020B0000
    TI_WSTRING_END = 0x020BFFFF


# ---------------------------------------------------------------------------
# Software Datatypes  (Softdatatype.cs)
# ---------------------------------------------------------------------------

class Softdatatype(IntEnum):
    VOID = 0
    BOOL = 1
    BYTE = 2
    CHAR = 3
    WORD = 4
    INT = 5
    DWORD = 6
    DINT = 7
    REAL = 8
    DATE = 9
    TIME_OF_DAY = 10
    TIME = 11
    S5TIME = 12
    S5COUNT = 13
    DATE_AND_TIME = 14
    INTERNET_TIME = 15
    ARRAY = 16
    STRUCT = 17
    ENDSTRUCT = 18
    STRING = 19
    POINTER = 20
    MULTI_FB = 21
    ANY = 22
    BLOCK_FB = 23
    BLOCK_FC = 24
    BLOCK_DB = 25
    BLOCK_SDB = 26
    MULTI_SFB = 27
    COUNTER = 28
    TIMER = 29
    IEC_COUNTER = 30
    IEC_TIMER = 31
    BLOCK_SFB = 32
    BLOCK_SFC = 33
    BLOCK_CB = 34
    BLOCK_SCB = 35
    BLOCK_OB = 36
    BLOCK_UDT = 37
    OFFSET = 38
    BLOCK_SDT = 39
    BBOOL = 40
    BLOCK_EXT = 41
    LREAL = 48
    ULINT = 49
    LINT = 50
    LWORD = 51
    USINT = 52
    UINT = 53
    UDINT = 54
    SINT = 55
    BCD8 = 56
    BCD16 = 57
    BCD32 = 58
    BCD64 = 59
    AREF = 60
    WCHAR = 61
    WSTRING = 62
    VARIANT = 63
    LTIME = 64
    LTOD = 65
    LDT = 66
    DTL = 67
    IEC_LTIMER = 68
    IEC_SCOUNTER = 69
    IEC_DCOUNTER = 70
    IEC_LCOUNTER = 71
    IEC_UCOUNTER = 72
    IEC_USCOUNTER = 73
    IEC_UDCOUNTER = 74
    IEC_ULCOUNTER = 75
    REMOTE = 96
    ERROR_STRUCT = 97
    NREF = 98
    VREF = 99
    FBTREF = 100
    CREF = 101
    VAREF = 102
    AOM_IDENT = 128
    EVENT_ANY = 129
    EVENT_ATT = 130
    FOLDER = 131
    AOM_AID = 132
    AOM_LINK = 133
    EVENT_HWINT = 134
    HW_ANY = 144
    HW_IOSYSTEM = 145
    HW_DPMASTER = 146
    HW_DEVICE = 147
    HW_DPSLAVE = 148
    HW_IO = 149
    HW_MODULE = 150
    HW_SUBMODULE = 151
    HW_HSC = 152
    HW_PWM = 153
    HW_PTO = 154
    HW_INTERFACE = 155
    HW_IEPORT = 156
    OB_ANY = 160
    OB_DELAY = 161
    OB_TOD = 162
    OB_CYCLIC = 163
    OB_ATT = 164
    CONN_ANY = 168
    CONN_PRG = 169
    CONN_OUC = 170
    CONN_R_ID = 171
    HW_NR = 172
    PORT = 173
    RTM = 174
    PIP = 175
    C_ALARM = 176
    C_ALARM_S = 177
    C_ALARM_8 = 178
    C_ALARM_8P = 179
    C_ALARM_T = 180
    C_AR_SEND = 181
    C_NOTIFY = 182
    C_NOTIFY_8P = 183
    OB_PCYCLE = 192
    OB_HWINT = 193
    OB_COMM = 194
    OB_DIAG = 195
    OB_TIMEERROR = 196
    OB_STARTUP = 197
    OPC_UA_LOCALIZED_TEXT_ENCODING_MASK = 200
    OPC_UA_BYTE_STRING_ACTUAL_LENGTH = 201
    DB_ANY = 208
    DB_WWW = 209
    DB_DYN = 210
    PARA = 253
    LABEL = 254
    UNDEFINED = 255
    NOT_CHOSEN = 256


# Name lookup for Softdatatype values
SOFTDATATYPE_NAMES: dict[int, str] = {v.value: v.name for v in Softdatatype}
