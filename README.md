# S7CommPlusDriver

Communication driver for data exchange with S7-1200/1500 PLCs.

## Development Status

This is currently a development release and is not intended for production use.

The goal is to develop a communication driver that provides access to the variable space
of S7-1200/1500 PLCs via symbolic access to so-called "optimized" memory areas.

This implementation is written entirely in C#. The OpenSSL library is used for TLS encryption.

## System Requirements

### CPU
The communication driver supports **exclusively** CPUs with firmware that enables secure communication
over the TLS protocol. As of the current state of knowledge, these are:
- S7-1200 with firmware >= V4.3 (TLS 1.3 from V4.5)
- S7-1500 with firmware >= V2.9

It is important to note that not only must a CPU with the corresponding firmware be present, but the project
must also have been configured in the development environment with the corresponding version. This is only
possible with TIA Portal version >= V17.

### OpenSSL
OpenSSL is used for TLS communication. If OpenSSL is installed in the corresponding version, a system path
to the installation directory should be set. The necessary DLLs are also included in the project and are
copied to the output directory in the required version (x86 or x64) during the build process.
The required DLLs with filenames depending on the operating system:

For 32-bit (x86):
- libcrypto-3.dll
- libssl-3.dll

For 64-bit (x64):
- libcrypto-3-x64.dll
- libssl-3-x64.dll

## Tested Communication
The following devices have been successfully tested:
- S7-1211 with firmware V4.5
- TIA PLCSim V17 (with Nettoplcsim)
- TIA PLCSim V18 (with Nettoplcsim)

## Analysis with Wireshark
Due to encryption, the transmitted data can no longer be viewed in Wireshark without additional information.
For driver development, a function is integrated into the project that outputs the negotiated secrets to a text file
(key_YYYYMMDD_hhmmss.log). With this information, Wireshark is able to decrypt and display the communication.
It is important that the capture includes the TLS connection establishment!

There are two ways to make this information available to Wireshark:
1. Place the log file in a directory and make it known to Wireshark. To do this, open *Menu* -> *Preferences* in Wireshark.
Under *Protocols*, select *TLS*, and in the *(Pre)-Master-Secret log filename* field, select the corresponding file.
2. Integrate the secrets directly into the Wireshark capture file.

For sharing with others for analysis, option 2 is preferred, since everything needed is contained in a single capture file.
The integration is done via the program "editcap.exe" in the Wireshark installation directory. For this, a capture must be
saved in Wireshark with the *.pcapng* extension.

Using the command line, the following command integrates the secrets from "key.log" into the capture "test-capture.pcapng"
and saves the result in the file "test-capture-with-keys.pcapng". When the latter file is opened in Wireshark, the
communication can be decrypted, decoded, and displayed according to the protocol.
The key.log file can be deleted afterwards if no longer needed.
```
"C:\Program Files\Wireshark\editcap.exe" --inject-secrets tls,key.log test-capture.pcapng test-capture-with-keys.pcapng
```

To simplify this process, I have written a small helper program with a graphical interface onto which files can be
dragged and dropped, and which calls editcap at the press of a button. The program is available here:

https://github.com/thomas-v2/PcapKeyInjector

In order for Wireshark to decode the S7comm-Plus protocol, the corresponding DLL must be placed in the Wireshark
installation directory. More details and the DLL download are available at SourceForge:

https://sourceforge.net/projects/s7commwireshark/

## PlcTag Class: Mapping PLC Datatypes to PlcTags

For some datatypes, it is necessary to know the type in advance in order to process the PLC response
and convert it into a meaningful .NET datatype. The PlcTag class is provided for this purpose.

The table lists all datatypes currently available in the PLC (as of TIA V18), along with the datatype
in which they are transmitted on the network in the S7comm-Plus protocol, and the resulting .NET datatype
in the PlcTag classes.

| Supported | PLC Datatype              | PLC Category        | PLC Info          | Network Datatype              | .NET Datatype PlcTag          | Notes                                             |
| :-------: | --------------------------| ------------------- | ----------------- | ----------------------------- | ----------------------------- | ------------------------------------------------- |
| &#x2713;  | AOM_IDENT                 | Hardware datatypes  |                   | ValueDWord                    | PlcTagDWord -> uint           |                                                   |
| &#x2713;  | Any                       | Pointers            | Parameter         | ValueUSIntArray[10]           | byte[10]                      |                                                   |
| &#x2713;  | Array[n..m]               |                     |                   |                               |                               | Access to individual elements directly possible   |
| &#x2713;  | Block_FB                  | Parameter types     | Parameter         | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | Block_FC                  | Parameter types     | Parameter         | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | Bool                      | Binary numbers      |                   | ValueBool                     | bool                          |                                                   |
| &#x2713;  | Byte                      | Bit sequences       |                   | ValueByte                     | byte                          |                                                   |
| &#x2713;  | CONN_ANY                  | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | CONN_OUC                  | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | CONN_PRG                  | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | CONN_R_ID                 | Hardware datatypes  |                   | ValueDWord                    | PlcTagDWord -> uint           |                                                   |
| &#x2713;  | CREF                      | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | Char                      | Character strings   |                   | ValueUSInt                    | char                          | Default encoding ISO-8859-1 for non-ASCII         |
| &#x2713;  | Counter                   | Parameter types     | Parameter         | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | Date                      | Date and time       |                   | ValueUInt                     | DateTime                      | TODO: Only date is valid!                         |
| &#x2713;  | Date_And_Time             | Date and time       |                   | ValueUSIntArray[8]            | DateTime                      |                                                   |
| &#x2713;  | DB_ANY                    | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | DB_DYN                    | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | DB_WWW                    | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | DInt                      | Integers            |                   | ValueDInt                     | int                           |                                                   |
| &#x2713;  | DTL                       | Date and time       |                   | ValueStruct / packed          | DateTime + uint (for ns)      | Nanoseconds external, as no .NET type with ns. Experimental! |
| &#x2713;  | DWord                     | Bit sequences       |                   | ValueDWord                    | uint                          |                                                   |
| &#x2713;  | EVENT_ANY                 | Hardware datatypes  |                   | ValueDWord                    | PlcTagDWord -> uint           |                                                   |
| &#x2713;  | EVENT_ATT                 | Hardware datatypes  |                   | ValueDWord                    | PlcTagDWord -> uint           |                                                   |
| &#x2713;  | EVENT_HWINT               | Hardware datatypes  |                   | ValueDWord                    | PlcTagDWord -> uint           |                                                   |
| &#x2713;  | ErrorStruct               |                     |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | HW_ANY                    | Hardware datatypes  |                   | ValueWord                     |                               |                                                   |
| &#x2713;  | HW_DEVICE                 | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_DPMASTER               | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_DPSLAVE                | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_HSC                    | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_IEPORT                 | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_INTERFACE              | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_IO                     | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_IOSYSTEM               | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_MODULE                 | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_PTO                    | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_PWM                    | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | HW_SUBMODULE              | Hardware datatypes  |                   | ValueWord                     | PlcTagWord -> ushort          |                                                   |
| &#x2713;  | IEC_COUNTER               | System datatypes    |                   | ValueStruct / packed          |                               | 33554462, access to individual elements directly possible |
| &#x2713;  | IEC_DCOUNTER              | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_LCOUNTER              | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_LTIMER                | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_SCOUNTER              | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_TIMER                 | System datatypes    |                   | ValueStruct / packed          |                               | 33554463, access to individual elements directly possible |
| &#x2713;  | IEC_UCOUNTER              | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_UDCOUNTER             | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_ULCOUNTER             | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | IEC_USCOUNTER             | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | Int                       | Integers            |                   | ValueInt                      | short                         |                                                   |
| &#x2713;  | LDT                       | Date and time       |                   | ValueTimestamp                | ulong                         |                                                   |
| &#x2713;  | LInt                      | Integers            |                   | ValueLInt                     | long                          |                                                   |
| &#x2713;  | LReal                     | Floating-point      |                   | ValueLReal                    | double                        |                                                   |
| &#x2713;  | LTime                     | Times               |                   | ValueTimespan                 | long                          | Count of ns                                       |
| &#x2713;  | LTime_Of_Day (LTOD)       | Date and time       |                   | ValueULInt                    | ulong                         | Count of ns since 00:00:00                        |
| &#x2713;  | LWord                     | Bit sequences       |                   | ValueLWord                    | ulong                         |                                                   |
| &#x2713;  | NREF                      | System datatypes    |                   | ValueStruct / packed          |                               | Access to individual elements directly possible   |
| &#x2713;  | OB_ANY                    | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_ATT                    | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_CYCLIC                 | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_DELAY                  | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_DIAG                   | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_HWINT                  | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_PCYCLE                 | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_STARTUP                | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_TIMEERROR              | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | OB_TOD                    | Hardware datatypes  |                   | ValueInt                      | PlcTagInt -> short            |                                                   |
| &#x2713;  | PIP                       | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | Pointer                   | Pointers            | Parameter         | ValueUSIntArray[6]            | byte[6]                       |                                                   |
| &#x2713;  | PORT                      | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | RTM                       | Hardware datatypes  |                   | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | Real                      | Floating-point      |                   | ValueReal                     | float                         |                                                   |
| &#x2713;  | Remote                    | Pointers            | Parameter         | ValueUSIntArray[10]           | PlcTagAny -> byte[10]         | Identical to Any pointer                          |
| &#x2713;  | S5Time                    | Times               |                   | ValueWord                     | ushort, ushort                | TODO: TimeBase, TimeValue. Unify?                 |
| &#x2713;  | SInt                      | Integers            |                   | ValueSInt                     | sbyte                         |                                                   |
| &#x2713;  | String                    | Character strings   |                   | ValueUSIntArray[stringlen + 2]| string                        | Default encoding ISO-8859-1 for non-ASCII         |
| &#x2713;  | Struct                    |                     |                   |                               |                               | Access to individual elements directly possible   |
| &#x2713;  | Time                      | Times               |                   | ValueDInt                     | int                           | Count of ms (signed)                              |
| &#x2713;  | Time_Of_Day (TOD)         | Date and time       |                   | ValueUDInt                    | uint                          | Count of ms since 00:00:00                        |
| &#x2713;  | Timer                     | Parameter types     | Parameter         | ValueUInt                     | PlcTagUInt -> ushort          |                                                   |
| &#x2713;  | UDInt                     | Integers            |                   | ValueUDInt                    | uint                          |                                                   |
| &#x2713;  | UInt                      | Integers            |                   | ValueUInt                     | ushort                        |                                                   |
| &#x2713;  | ULInt                     | Integers            |                   | ValueULInt                    | ulong                         |                                                   |
| &#x2713;  | USInt                     | Integers            |                   | ValueUSInt                    | byte                          |                                                   |
| &#x2717;  | Variant                   | Pointers            | Parameter         |                               |                               | Does not receive an address                       |
| &#x2713;  | WChar                     | Character strings   |                   | ValueUInt                     | char                          |                                                   |
| &#x2713;  | WString                   | Character strings   |                   | ValueUIntArray[stringlen + 2] | string                        |                                                   |
| &#x2713;  | Word                      | Bit sequences       |                   | ValueWord                     | ushort                        |                                                   |

## License

Unless otherwise noted, all source code is licensed under the GNU Lesser General Public License,
version 3 or later.

## Authors

* **Thomas Wiens** - *Initial work* - [thomas-v2](https://github.com/thomas-v2)
