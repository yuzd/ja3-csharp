// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography;
using System.Text;

namespace Ja3Fingerprint
{
    // SSL3/TLS protocol frames definitions . https://halfrost.com/https-extensions/
    //https://github.com/lafaspot/ja3_4java/blob/cf2c574eea699a72db57312627d1ca2ed8809131/src/main/java/com/lafaspot/ja3_4java/JA3Signature.java#L229
    internal enum TlsContentType : byte
    {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        AppData = 23
    }

    internal enum CurveType : byte
    {
        CurveP256 = 23,
        CurveP384 = 24,
        CurveP521 = 25,
        X25519 = 29,
    }
    internal enum EcPointFormat : byte
    {
        uncompressed = 0,
        ansiX962_compressed_prime = 1,
        ansiX962_compressed_char2 = 2,
    }
    internal enum TlsHandshakeType : byte
    {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        NewSessionTicket = 4,
        EndOfEarlyData = 5,
        EncryptedExtensions = 8,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20,
        KeyEpdate = 24,
        MessageHash = 254
    }

    internal enum TlsAlertLevel : byte
    {
        Warning = 1,
        Fatal = 2,
    }

    internal enum TlsAlertDescription : byte
    {
        CloseNotify = 0, // warning
        UnexpectedMessage = 10, // error
        BadRecordMac = 20, // error
        DecryptionFailed = 21, // reserved
        RecordOverflow = 22, // error
        DecompressionFail = 30, // error
        HandshakeFailure = 40, // error
        BadCertificate = 42, // warning or error
        UnsupportedCert = 43, // warning or error
        CertificateRevoked = 44, // warning or error
        CertificateExpired = 45, // warning or error
        CertificateUnknown = 46, // warning or error
        IllegalParameter = 47, // error
        UnknownCA = 48, // error
        AccessDenied = 49, // error
        DecodeError = 50, // error
        DecryptError = 51, // error
        ExportRestriction = 60, // reserved
        ProtocolVersion = 70, // error
        InsuffientSecurity = 71, // error
        InternalError = 80, // error
        UserCanceled = 90, // warning or error
        NoRenegotiation = 100, // warning
        UnsupportedExt = 110, // error
    }
    // // Elliptic curve points 0x0a    // Elliptic curve point formats 0x0b
    internal enum ExtensionType : ushort
    {
        server_name = 0,
        max_fragment_length = 1,
        client_certificate_url = 2,
        trusted_ca_keys = 3,
        truncated_hmac = 4,
        status_request = 5,
        user_mapping = 6,
        client_authz = 7,
        server_authz = 8,
        cert_type = 9,
        supported_groups = 10,//  Elliptic curve points
        ec_point_formats = 11, // Elliptic curve point formats
        srp = 12,
        signature_algorithms = 13,
        use_srtp = 14,
        heartbeat = 15,
        application_layer_protocol_negotiation = 16,
        status_request_v2 = 17,
        signed_certificate_timestamp = 18,
        client_certificate_type = 19,
        server_certificate_type = 20,
        padding = 21,
        encrypt_then_mac = 22,
        extended_master_secret = 23,
        token_binding = 24,
        cached_info = 25,
        tls_lts = 26,
        compress_certificate = 27,
        record_size_limit = 28,
        pwd_protect = 29,
        pwd_clear = 30,
        password_salt = 31,
        session_ticket = 35,
        pre_shared_key = 41,
        early_data = 42,
        supported_versions = 43,
        cookie = 44,
        psk_key_exchange_modes = 45,
        certificate_authorities = 47,
        oid_filters = 48,
        post_handshake_auth = 49,
        signature_algorithms_cert = 50,
        key_share = 51,
        extensionQUICTransportParams = 57,
        extensionCustom = 1234,  // not IANA assigned
        extensionNextProtoNeg = 13172, // not IANA assigned
        extensionApplicationSettings = 17513, // not IANA assigned
        extensionChannelID=30032,// not IANA assigned
        renegotiation_info = 65281
    }

    internal struct TlsFrameHeader
    {
        public TlsContentType Type;
        public SslProtocols Version;
        public String VersionStr;
        public int Length;

        public override string ToString() => $"{Version}:{Type}[{Length}]";
    }



    internal static class TlsFrameHelper
    {
        public const int HeaderSize = 5;

        [Flags]
        public enum ProcessingOptions
        {
            ServerName = 0x1,
            ApplicationProtocol = 0x2,
            Versions = 0x4,
            CipherSuites = 0x8,
            All = 0x7FFFFFFF,
        }

        [Flags]
        public enum ApplicationProtocolInfo
        {
            None = 0,
            Http11 = 1,
            Http2 = 2,
            Other = 128
        }

        internal struct TlsFrameInfo
        {
            internal TlsCipherSuite[]? _ciphers;
            internal List<ExtensionType>? _extensions;
            internal List<CurveType>? _supportedgroups;
            internal List<EcPointFormat>? _ecPointFormats;
            public TlsFrameHeader Header;
            public TlsHandshakeType HandshakeType;
            public SslProtocols SupportedVersions;
            public string TargetName;
            public ApplicationProtocolInfo ApplicationProtocols;
            public TlsAlertDescription AlertDescription;
            public ReadOnlyMemory<TlsCipherSuite> TlsCipherSuites
            {
                get
                {
                    return _ciphers == null ? ReadOnlyMemory<TlsCipherSuite>.Empty : new ReadOnlyMemory<TlsCipherSuite>(_ciphers);
                }
            }

            public ReadOnlyMemory<ExtensionType> Extensions
            {
                get
                {
                    return _extensions == null
                        ? ReadOnlyMemory<ExtensionType>.Empty
                        : new ReadOnlyMemory<ExtensionType>(_extensions.ToArray());
                }
            }

            public ReadOnlyMemory<CurveType> SupportedGroups
            {
                get
                {
                    return _supportedgroups == null
                        ? ReadOnlyMemory<CurveType>.Empty
                        : new ReadOnlyMemory<CurveType>(_supportedgroups.ToArray());
                }
            }

            public ReadOnlyMemory<EcPointFormat> EcPointFormats
            {
                get
                {
                    return _ecPointFormats == null
                        ? ReadOnlyMemory<EcPointFormat>.Empty
                        : new ReadOnlyMemory<EcPointFormat>(_ecPointFormats.ToArray());
                }
            }

            public (string, string,string) getSig()
            {
                StringBuilder sb = new StringBuilder();
                List<string> s2b = new List<string>();
                sb.Append(Header.VersionStr);
                sb.Append(",");
                if (_ciphers != null)
                {
                    _ciphers = _ciphers.Where(r => r != TlsCipherSuite.TLS_NULL_WITH_NULL_NULL).ToArray();
                    sb.Append(string.Join("-", _ciphers.Select(r => (int)r)));
                    s2b.Add(string.Join("-", _ciphers.Select(r => r.ToString())));
                }
                sb.Append(",");
                if (_extensions != null)
                {
                    sb.Append(string.Join("-", _extensions.Select(r => (int)r)));
                    s2b.Add(string.Join("-", _extensions.Select(r => r.ToString())));
                }
                sb.Append(",");
                if (_supportedgroups != null)
                {
                    sb.Append(string.Join("-", _supportedgroups.Select(r => (int)r)));
                    s2b.Add(string.Join("-", _supportedgroups.Select(r => r.ToString())));
                }
                sb.Append(",");
                if (_ecPointFormats != null)
                {
                    sb.Append(string.Join("-", _ecPointFormats.Select(r => (int)r)));
                    s2b.Add(string.Join("-", _ecPointFormats.Select(r => r.ToString())));
                }
                s2b.Add(Header.Version.ToString());
                String str = sb.ToString();
                using var md5 = MD5.Create();
                var result = md5.ComputeHash(Encoding.ASCII.GetBytes(str));
                var strResult = BitConverter.ToString(result);
                var sig = strResult.Replace("-", "").ToLower();
                return (str, sig, string.Join('|', s2b));
            }


           

            public override string ToString()
            {

                if (Header.Type == TlsContentType.Handshake)
                {
                    if (HandshakeType == TlsHandshakeType.ClientHello)
                    {

                        return $"{Header.Version}:{HandshakeType}[{Header.Length}] TargetName='{TargetName}' SupportedVersion='{SupportedVersions}' ApplicationProtocols='{ApplicationProtocols}'-->sig:{getSig()}";
                    }
                    else if (HandshakeType == TlsHandshakeType.ServerHello)
                    {
                        return $"{Header.Version}:{HandshakeType}[{Header.Length}] SupportedVersion='{SupportedVersions}' ApplicationProtocols='{ApplicationProtocols}'";
                    }
                    else
                    {
                        return $"{Header.Version}:{HandshakeType}[{Header.Length}] SupportedVersion='{SupportedVersions}'";
                    }
                }
                else
                {
                    return $"{Header.Version}:{Header.Type}[{Header.Length}]";
                }
            }
        }

        internal delegate bool HelloExtensionCallback(ref TlsFrameInfo info, ExtensionType type, ReadOnlySpan<byte> extensionsData);

        private static byte[] s_protocolMismatch13 = new byte[] { (byte)TlsContentType.Alert, 3, 4, 0, 2, 2, 70 };
        private static byte[] s_protocolMismatch12 = new byte[] { (byte)TlsContentType.Alert, 3, 3, 0, 2, 2, 70 };
        private static byte[] s_protocolMismatch11 = new byte[] { (byte)TlsContentType.Alert, 3, 2, 0, 2, 2, 70 };
        private static byte[] s_protocolMismatch10 = new byte[] { (byte)TlsContentType.Alert, 3, 1, 0, 2, 2, 70 };
        private static byte[] s_protocolMismatch30 = new byte[] { (byte)TlsContentType.Alert, 3, 0, 0, 2, 2, 40 };

        private const int UInt24Size = 3;
        private const int RandomSize = 32;
        private const int OpaqueType1LengthSize = sizeof(byte);
        private const int OpaqueType2LengthSize = sizeof(ushort);
        private const int ProtocolVersionMajorOffset = 0;
        private const int ProtocolVersionMinorOffset = 1;
        private const int ProtocolVersionSize = 2;
        private const int ProtocolVersionTlsMajorValue = 3;

        // Per spec "AllowUnassigned flag MUST be set". See comment above DecodeString() for more details.
        private static readonly IdnMapping s_idnMapping = new IdnMapping() { AllowUnassigned = true };
        private static readonly Encoding s_encoding = Encoding.GetEncoding("utf-8", new EncoderExceptionFallback(), new DecoderExceptionFallback());

        internal static bool TryGetFrameHeader(ReadOnlySpan<byte> frame, ref TlsFrameHeader header)
        {
            bool result = frame.Length > 4;

            if (frame.Length >= 1)
            {
                header.Type = (TlsContentType)frame[0];

                if (frame.Length >= 3)
                {
                    // SSLv3, TLS or later
                    if (frame[1] == 3)
                    {
                        if (frame.Length > 4)
                        {
                            header.Length = ((frame[3] << 8) | frame[4]);
                        }

                        var ver = frame[9];
                        header.Version = TlsMinorVersionToProtocol(frame[10]);
                        header.VersionStr = (((ver & 255) << 8) + (frame[10] & 255)).ToString();
                    }
                    else
                    {
                        header.Length = -1;
                        header.Version = SslProtocols.None;
                    }
                }
            }

            return result;
        }

        // Returns frame size e.g. header + content
        public static int GetFrameSize(ReadOnlySpan<byte> frame)
        {
            if (frame.Length < 5 || frame[1] < 3)
            {
                return -1;
            }

            return ((frame[3] << 8) | frame[4]) + HeaderSize;
        }

        /**
   * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described here:
   * https://tools.ietf.org/html/draft-davidben-tls-grease-01.
   */
        private static int[] GREASE = new int[] { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa };

        /**
     * Check if TLS protocols cipher, extension, named groups, signature algorithms and version values match GREASE values. <blockquote
     * cite="https://tools.ietf.org/html/draft-ietf-tls-grease"> GREASE (Generate Random Extensions And Sustain Extensibility), a mechanism to prevent
     * extensibility failures in the TLS ecosystem. It reserves a set of TLS protocol values that may be advertised to ensure peers correctly handle
     * unknown values </blockquote>
     *
     * @param value value to be checked against GREASE values
     * @return false if value matches GREASE value, true otherwise
     * @see <a href="https://tools.ietf.org/html/draft-ietf-tls-grease">draft-ietf-tls-grease</a>
     */
        private static bool isNotGrease(int value)
        {
            for (int i = 0; i < GREASE.Length; i++)
            {
                if (value == GREASE[i])
                {
                    return false;
                }
            }

            return true;
        }

        // This function will try to parse TLS hello frame and fill details in provided info structure.
        // If frame was fully processed without any error, function returns true.
        // Otherwise it returns false and info may have partial data.
        // It is OK to call it again if more data becomes available.
        // It is also possible to limit what information is processed.
        // If callback delegate is provided, it will be called on ALL extensions.
        internal static bool TryGetFrameInfo(ReadOnlySpan<byte> frame, ref TlsFrameInfo info, ProcessingOptions options = ProcessingOptions.All, HelloExtensionCallback? callback = null)
        {
            const int HandshakeTypeOffset = 5;
            if (frame.Length < HeaderSize)
            {
                return false;
            }

            // This will not fail since we have enough data.
            bool gotHeader = TryGetFrameHeader(frame, ref info.Header);
            Debug.Assert(gotHeader);

            info.SupportedVersions = info.Header.Version;

            if (info.Header.Type == TlsContentType.Alert)
            {
                TlsAlertLevel level = default;
                TlsAlertDescription description = default;
                if (TryGetAlertInfo(frame, ref level, ref description))
                {
                    info.AlertDescription = description;
                    return true;
                }

                return false;
            }

            if (info.Header.Type != TlsContentType.Handshake || frame.Length <= HandshakeTypeOffset)
            {
                return false;
            }

            info.HandshakeType = (TlsHandshakeType)frame[HandshakeTypeOffset];

            // Check if we have full frame.
            bool isComplete = frame.Length >= HeaderSize + info.Header.Length;

            if (((int)info.Header.Version >= (int)SslProtocols.Tls) &&
                (info.HandshakeType == TlsHandshakeType.ClientHello || info.HandshakeType == TlsHandshakeType.ServerHello))
            {
                if (!TryParseHelloFrame(frame.Slice(HeaderSize), ref info, options, callback))
                {
                    isComplete = false;
                }
            }

            return isComplete;
        }

        // This is similar to TryGetFrameInfo but it will only process SNI.
        // It returns TargetName as string or NULL if SNI is missing or parsing error happened.
        public static string? GetServerName(ReadOnlySpan<byte> frame)
        {
            TlsFrameInfo info = default;
            if (!TryGetFrameInfo(frame, ref info, ProcessingOptions.ServerName))
            {
                return null;
            }

            return info.TargetName;
        }

        // This function will parse TLS Alert message and it will return alert level and description.
        public static bool TryGetAlertInfo(ReadOnlySpan<byte> frame, ref TlsAlertLevel level, ref TlsAlertDescription description)
        {
            if (frame.Length < 7 || frame[0] != (byte)TlsContentType.Alert)
            {
                return false;
            }

            level = (TlsAlertLevel)frame[5];
            description = (TlsAlertDescription)frame[6];

            return true;
        }

        private static byte[] CreateProtocolVersionAlert(SslProtocols version) =>
            version switch
            {
                SslProtocols.Tls13 => s_protocolMismatch13,
                SslProtocols.Tls12 => s_protocolMismatch12,
                SslProtocols.Tls11 => s_protocolMismatch11,
                SslProtocols.Tls => s_protocolMismatch10,
#pragma warning disable 0618
                SslProtocols.Ssl3 => s_protocolMismatch30,
#pragma warning restore 0618
                _ => Array.Empty<byte>(),
            };

        private static bool TryParseHelloFrame(ReadOnlySpan<byte> sslHandshake, ref TlsFrameInfo info, ProcessingOptions options, HelloExtensionCallback? callback)
        {
            // https://tools.ietf.org/html/rfc6101#section-5.6
            // struct {
            //     HandshakeType msg_type;    /* handshake type */
            //     uint24 length;             /* bytes in message */
            //     select (HandshakeType) {
            //         ...
            //         case client_hello: ClientHello;
            //         case server_hello: ServerHello;
            //         ...
            //     } body;
            // } Handshake;
            const int HandshakeTypeOffset = 0;
            const int HelloLengthOffset = HandshakeTypeOffset + sizeof(TlsHandshakeType);
            const int HelloOffset = HelloLengthOffset + UInt24Size;

            if (sslHandshake.Length < HelloOffset ||
                ((TlsHandshakeType)sslHandshake[HandshakeTypeOffset] != TlsHandshakeType.ClientHello &&
                 (TlsHandshakeType)sslHandshake[HandshakeTypeOffset] != TlsHandshakeType.ServerHello))
            {
                return false;
            }

            int helloLength = ReadUInt24BigEndian(sslHandshake.Slice(HelloLengthOffset));
            ReadOnlySpan<byte> helloData = sslHandshake.Slice(HelloOffset);

            if (helloData.Length < helloLength)
            {
                return false;
            }

            // ProtocolVersion may be different from frame header.
            if (helloData[ProtocolVersionMajorOffset] == ProtocolVersionTlsMajorValue)
            {
                info.SupportedVersions |= TlsMinorVersionToProtocol(helloData[ProtocolVersionMinorOffset]);
            }

            return (TlsHandshakeType)sslHandshake[HandshakeTypeOffset] == TlsHandshakeType.ClientHello ?
                        TryParseClientHello(helloData.Slice(0, helloLength), ref info, options, callback) :
                        TryParseServerHello(helloData.Slice(0, helloLength), ref info, options, callback);
        }

        private static bool TryParseClientHello(ReadOnlySpan<byte> clientHello, ref TlsFrameInfo info, ProcessingOptions options, HelloExtensionCallback? callback)
        {
            // Basic structure: https://tools.ietf.org/html/rfc6101#section-5.6.1.2
            // Extended structure: https://tools.ietf.org/html/rfc3546#section-2.1
            // struct {
            //     ProtocolVersion client_version; // 2x uint8
            //     Random random; // 32 bytes
            //     SessionID session_id; // opaque type
            //     CipherSuite cipher_suites<2..2^16-1>; // opaque type
            //     CompressionMethod compression_methods<1..2^8-1>; // opaque type
            //     Extension client_hello_extension_list<0..2^16-1>;
            // } ClientHello;

            ReadOnlySpan<byte> p = SkipBytes(clientHello, ProtocolVersionSize + RandomSize);

            // Skip SessionID (max size 32 => size fits in 1 byte)
            p = SkipOpaqueType1(p);

            if (options.HasFlag(ProcessingOptions.CipherSuites))
            {
                TryGetCipherSuites(p, ref info);
            }
            // Skip cipher suites (max size 2^16-1 => size fits in 2 bytes)
            p = SkipOpaqueType2(p);

            // Skip compression methods (max size 2^8-1 => size fits in 1 byte)
            p = SkipOpaqueType1(p);

            // is invalid structure or no extensions?
            if (p.IsEmpty)
            {
                return false;
            }

            // client_hello_extension_list (max size 2^16-1 => size fits in 2 bytes)
            int extensionListLength = BinaryPrimitives.ReadUInt16BigEndian(p);
            p = SkipBytes(p, sizeof(ushort));
            if (extensionListLength != p.Length)
            {
                return false;
            }

            return TryParseHelloExtensions(p, ref info, options, callback);
        }

        private static bool TryParseServerHello(ReadOnlySpan<byte> serverHello, ref TlsFrameInfo info, ProcessingOptions options, HelloExtensionCallback? callback)
        {
            // Basic structure: https://tools.ietf.org/html/rfc6101#section-5.6.1.3
            // Extended structure: https://tools.ietf.org/html/rfc3546#section-2.2
            // struct {
            //   ProtocolVersion server_version;
            //   Random random;
            //   SessionID session_id;
            //   CipherSuite cipher_suite;
            //   CompressionMethod compression_method;
            //   Extension server_hello_extension_list<0..2^16-1>;
            // }
            // ServerHello;
            const int CipherSuiteLength = 2;
            const int CompressionMethiodLength = 1;

            ReadOnlySpan<byte> p = SkipBytes(serverHello, ProtocolVersionSize + RandomSize);
            // Skip SessionID (max size 32 => size fits in 1 byte)
            p = SkipOpaqueType1(p);
            p = SkipBytes(p, CipherSuiteLength + CompressionMethiodLength);

            // is invalid structure or no extensions?
            if (p.IsEmpty)
            {
                return false;
            }

            // client_hello_extension_list (max size 2^16-1 => size fits in 2 bytes)
            int extensionListLength = BinaryPrimitives.ReadUInt16BigEndian(p);
            p = SkipBytes(p, sizeof(ushort));
            if (extensionListLength != p.Length)
            {
                return false;
            }

            return TryParseHelloExtensions(p, ref info, options, callback);
        }

        // This is common for ClientHello and ServerHello.
        private static bool TryParseHelloExtensions(ReadOnlySpan<byte> extensions, ref TlsFrameInfo info, ProcessingOptions options, HelloExtensionCallback? callback)
        {
            const int ExtensionHeader = 4;
            bool isComplete = true;

            while (extensions.Length >= ExtensionHeader)
            {
                ExtensionType extensionType = (ExtensionType)BinaryPrimitives.ReadUInt16BigEndian(extensions);
                extensions = SkipBytes(extensions, sizeof(ushort));

                ushort extensionLength = BinaryPrimitives.ReadUInt16BigEndian(extensions);
                extensions = SkipBytes(extensions, sizeof(ushort));
                if (extensions.Length < extensionLength)
                {
                    isComplete = false;
                    break;
                }

                ReadOnlySpan<byte> extensionData = extensions.Slice(0, extensionLength);

                if (extensionType == ExtensionType.server_name && options.HasFlag(ProcessingOptions.ServerName))
                {
                    if (!TryGetSniFromServerNameList(extensionData, out string? sni))
                    {
                        return false;
                    }

                    info.TargetName = sni!;
                }
                else if (extensionType == ExtensionType.supported_versions && options.HasFlag(ProcessingOptions.Versions))
                {
                    if (!TryGetSupportedVersionsFromExtension(extensionData, out SslProtocols versions))
                    {
                        return false;
                    }

                    info.SupportedVersions |= versions;
                }
                else if (extensionType == ExtensionType.application_layer_protocol_negotiation && options.HasFlag(ProcessingOptions.ApplicationProtocol))
                {
                    if (!TryGetApplicationProtocolsFromExtension(extensionData, out ApplicationProtocolInfo alpn))
                    {
                        return false;
                    }

                    info.ApplicationProtocols |= alpn;
                }

                if (extensionType == ExtensionType.supported_groups)
                {
                    if (!TryGetSupportedGroups(extensionData, ref info))
                    {
                        return false;
                    }

                }

                if (extensionType == ExtensionType.ec_point_formats)
                {
                    if (!TryGetEcPointsFormats(extensionData, ref info))
                    {
                        return false;
                    }
                }

                info._extensions ??= new List<ExtensionType>();
                if (isNotGrease((int)extensionType))
                {
                    info._extensions.Add(extensionType);
                }
                callback?.Invoke(ref info, extensionType, extensionData);
                extensions = extensions.Slice(extensionLength);
            }

            return isComplete;
        }

        private static bool TryGetSniFromServerNameList(ReadOnlySpan<byte> serverNameListExtension, out string? sni)
        {
            // https://tools.ietf.org/html/rfc3546#section-3.1
            // struct {
            //     ServerName server_name_list<1..2^16-1>
            // } ServerNameList;
            // ServerNameList is an opaque type (length of sufficient size for max data length is prepended)
            const int ServerNameListOffset = sizeof(ushort);
            sni = null;

            if (serverNameListExtension.Length < ServerNameListOffset)
            {
                return false;
            }

            int serverNameListLength = BinaryPrimitives.ReadUInt16BigEndian(serverNameListExtension);
            ReadOnlySpan<byte> serverNameList = serverNameListExtension.Slice(ServerNameListOffset);

            if (serverNameListLength != serverNameList.Length)
            {
                return false;
            }

            ReadOnlySpan<byte> serverName = serverNameList.Slice(0, serverNameListLength);

            sni = GetSniFromServerName(serverName, out bool invalid);
            return invalid == false;
        }

        private static string? GetSniFromServerName(ReadOnlySpan<byte> serverName, out bool invalid)
        {
            // https://tools.ietf.org/html/rfc3546#section-3.1
            // struct {
            //     NameType name_type;
            //     select (name_type) {
            //         case host_name: HostName;
            //     } name;
            // } ServerName;
            // ServerName is an opaque type (length of sufficient size for max data length is prepended)
            const int NameTypeOffset = 0;
            const int HostNameStructOffset = NameTypeOffset + sizeof(NameType);
            if (serverName.Length < HostNameStructOffset)
            {
                invalid = true;
                return null;
            }

            // Following can underflow but it is ok due to equality check below
            NameType nameType = (NameType)serverName[NameTypeOffset];
            ReadOnlySpan<byte> hostNameStruct = serverName.Slice(HostNameStructOffset);
            if (nameType != NameType.HostName)
            {
                invalid = true;
                return null;
            }

            return GetSniFromHostNameStruct(hostNameStruct, out invalid);
        }

        private static string? GetSniFromHostNameStruct(ReadOnlySpan<byte> hostNameStruct, out bool invalid)
        {
            // https://tools.ietf.org/html/rfc3546#section-3.1
            // HostName is an opaque type (length of sufficient size for max data length is prepended)
            const int HostNameLengthOffset = 0;
            const int HostNameOffset = HostNameLengthOffset + sizeof(ushort);

            int hostNameLength = BinaryPrimitives.ReadUInt16BigEndian(hostNameStruct);
            ReadOnlySpan<byte> hostName = hostNameStruct.Slice(HostNameOffset);
            if (hostNameLength != hostName.Length)
            {
                invalid = true;
                return null;
            }

            invalid = false;
            return DecodeString(hostName);
        }

        private static bool TryGetSupportedVersionsFromExtension(ReadOnlySpan<byte> extensionData, out SslProtocols protocols)
        {
            // https://tools.ietf.org/html/rfc8446#section-4.2.1
            // struct {
            // select(Handshake.msg_type) {
            //  case client_hello:
            //    ProtocolVersion versions<2..254 >;
            //
            //  case server_hello: /* and HelloRetryRequest */
            //    ProtocolVersion selected_version;
            // };
            const int VersionListLengthOffset = 0;
            const int VersionListNameOffset = VersionListLengthOffset + sizeof(byte);
            const int VersionLength = 2;

            protocols = SslProtocols.None;

            byte supportedVersionLength = extensionData[VersionListLengthOffset];
            extensionData = extensionData.Slice(VersionListNameOffset);

            if (extensionData.Length != supportedVersionLength)
            {
                return false;
            }

            // Get list of protocols we support.I nore the rest.
            while (extensionData.Length >= VersionLength)
            {
                if (extensionData[ProtocolVersionMajorOffset] == ProtocolVersionTlsMajorValue)
                {
                    protocols |= TlsMinorVersionToProtocol(extensionData[ProtocolVersionMinorOffset]);
                }

                extensionData = extensionData.Slice(VersionLength);
            }

            return true;
        }

        private static bool TryGetEcPointsFormats(ReadOnlySpan<byte> extensionData, ref TlsFrameInfo info)
        {
            const int VersionListLengthOffset = 0;
            const int VersionListNameOffset = VersionListLengthOffset + sizeof(byte);
            byte supportedVersionLength = extensionData[VersionListLengthOffset];
            ReadOnlySpan<byte> alpnList = extensionData.Slice(VersionListNameOffset);

            if (alpnList.Length != supportedVersionLength)
            {
                return false;
            }

            info._ecPointFormats = new List<EcPointFormat>();
            foreach (var code in alpnList)
            {
                if (code > 2) continue;
                EcPointFormat t = (EcPointFormat)code;
                info._ecPointFormats.Add(t);
            }

            return true;
        }
        private static bool TryGetSupportedGroups(ReadOnlySpan<byte> extensionData, ref TlsFrameInfo info)
        {
            const int SupportedGroupsOffset = 1;
            const int SupportedGroupsListOffset = SupportedGroupsOffset + sizeof(byte);
            byte supportedVersionLength = extensionData[SupportedGroupsOffset];
            extensionData = extensionData.Slice(SupportedGroupsListOffset);
            if (extensionData.Length != supportedVersionLength)
            {
                return false;
            }

            info._supportedgroups = new List<CurveType>();
            const int VersionLength = 2;
            while (extensionData.Length >= VersionLength)
            {
                if (extensionData[ProtocolVersionMajorOffset] == 0)
                {
                    CurveType t = (CurveType)extensionData[ProtocolVersionMinorOffset];
                    info._supportedgroups.Add(t);
                }

                extensionData = extensionData.Slice(VersionLength);
            }
            return true;
        }

        private static bool TryGetApplicationProtocolsFromExtension(ReadOnlySpan<byte> extensionData, out ApplicationProtocolInfo alpn)
        {
            // https://tools.ietf.org/html/rfc7301#section-3.1
            // opaque ProtocolName<1..2 ^ 8 - 1 >;
            //
            // struct {
            //   ProtocolName protocol_name_list<2..2^16-1>
            // }
            // ProtocolNameList;
            const int AlpnListLengthOffset = 0;
            const int AlpnListOffset = AlpnListLengthOffset + sizeof(short);

            alpn = ApplicationProtocolInfo.None;

            if (extensionData.Length < AlpnListOffset)
            {
                return false;
            }

            int AlpnListLength = BinaryPrimitives.ReadUInt16BigEndian(extensionData);
            ReadOnlySpan<byte> alpnList = extensionData.Slice(AlpnListOffset);
            if (AlpnListLength != alpnList.Length)
            {
                return false;
            }

            while (!alpnList.IsEmpty)
            {
                byte protocolLength = alpnList[0];
                if (alpnList.Length < protocolLength + 1)
                {
                    return false;
                }

                ReadOnlySpan<byte> protocol = alpnList.Slice(1, protocolLength);
                if (protocolLength == 2)
                {
                    if (protocol.SequenceEqual(SslApplicationProtocol.Http2.Protocol.Span))
                    {
                        alpn |= ApplicationProtocolInfo.Http2;
                    }
                    else
                    {
                        alpn |= ApplicationProtocolInfo.Other;
                    }
                }
                else if (protocolLength == SslApplicationProtocol.Http11.Protocol.Length &&
                         protocol.SequenceEqual(SslApplicationProtocol.Http11.Protocol.Span))
                {
                    alpn |= ApplicationProtocolInfo.Http11;
                }
                else
                {
                    alpn |= ApplicationProtocolInfo.Other;
                }

                alpnList = alpnList.Slice(protocolLength + 1);
            }

            return true;
        }

        private static bool TryGetCipherSuites(ReadOnlySpan<byte> bytes, ref TlsFrameInfo info)
        {
            if (bytes.Length < OpaqueType2LengthSize)
            {
                return false;
            }

            ushort length = BinaryPrimitives.ReadUInt16BigEndian(bytes);
            if (bytes.Length < OpaqueType2LengthSize + length)
            {
                return false;
            }

            bytes = bytes.Slice(OpaqueType2LengthSize, length);
            int count = length / 2;

            info._ciphers = new TlsCipherSuite[count];
            for (int i = 0; i < count; i++)
            {
                TlsCipherSuite t = (TlsCipherSuite)BinaryPrimitives.ReadUInt16BigEndian(bytes.Slice(i * 2, 2));
                if (isNotGrease((int)t))
                {
                    info._ciphers[i] = t;
                }
            }

            return true;
        }

        private static SslProtocols TlsMinorVersionToProtocol(byte value)
        {
            return value switch
            {
                4 => SslProtocols.Tls13,
                3 => SslProtocols.Tls12,
                2 => SslProtocols.Tls11,
                1 => SslProtocols.Tls,
#pragma warning disable 0618
                0 => SslProtocols.Ssl3,
#pragma warning restore 0618
                _ => SslProtocols.None,
            };
        }


        private static string? DecodeString(ReadOnlySpan<byte> bytes)
        {
            // https://tools.ietf.org/html/rfc3546#section-3.1
            // Per spec:
            //   If the hostname labels contain only US-ASCII characters, then the
            //   client MUST ensure that labels are separated only by the byte 0x2E,
            //   representing the dot character U+002E (requirement 1 in section 3.1
            //   of [IDNA] notwithstanding). If the server needs to match the HostName
            //   against names that contain non-US-ASCII characters, it MUST perform
            //   the conversion operation described in section 4 of [IDNA], treating
            //   the HostName as a "query string" (i.e. the AllowUnassigned flag MUST
            //   be set). Note that IDNA allows labels to be separated by any of the
            //   Unicode characters U+002E, U+3002, U+FF0E, and U+FF61, therefore
            //   servers MUST accept any of these characters as a label separator.  If
            //   the server only needs to match the HostName against names containing
            //   exclusively ASCII characters, it MUST compare ASCII names case-
            //   insensitively.

            string idnEncodedString;
            try
            {
                idnEncodedString = s_encoding.GetString(bytes);
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

            try
            {
                return s_idnMapping.GetUnicode(idnEncodedString);
            }
            catch (ArgumentException)
            {
                // client has not done IDN mapping
                return idnEncodedString;
            }
        }

        private static int ReadUInt24BigEndian(ReadOnlySpan<byte> bytes)
        {
            return (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
        }

        private static ReadOnlySpan<byte> SkipBytes(ReadOnlySpan<byte> bytes, int numberOfBytesToSkip)
        {
            return (numberOfBytesToSkip < bytes.Length) ? bytes.Slice(numberOfBytesToSkip) : ReadOnlySpan<byte>.Empty;
        }

        // Opaque type is of structure:
        //   - length (minimum number of bytes to hold the max value)
        //   - data (length bytes)
        // We will only use opaque types which are of max size: 255 (length = 1) or 2^16-1 (length = 2).
        // We will call them SkipOpaqueType`length`
        private static ReadOnlySpan<byte> SkipOpaqueType1(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < OpaqueType1LengthSize)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            byte length = bytes[0];
            int totalBytes = OpaqueType1LengthSize + length;

            return SkipBytes(bytes, totalBytes);
        }

        private static ReadOnlySpan<byte> SkipOpaqueType2(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < OpaqueType2LengthSize)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            ushort length = BinaryPrimitives.ReadUInt16BigEndian(bytes);
            int totalBytes = OpaqueType2LengthSize + length;

            return SkipBytes(bytes, totalBytes);
        }

        private enum NameType : byte
        {
            HostName = 0x00
        }
    }

    [Flags]
    internal enum SslProtocols
    {
        /// <summary>Allows the operating system to choose the best protocol to use, and to block protocols that are not secure. Unless your app has a specific reason not to, you should use this field.</summary>
        None = 0,
        /// <summary>Specifies the SSL 2.0 protocol. SSL 2.0 has been superseded by the TLS protocol and is provided for backward compatibility only.</summary>
        Ssl2 = 12, // 0x0000000C
        /// <summary>Specifies the SSL 3.0 protocol. SSL 3.0 has been superseded by the TLS protocol and is provided for backward compatibility only.</summary>
        Ssl3 = 48, // 0x00000030
        /// <summary>Specifies the TLS 1.0 security protocol.  TLS 1.0 is provided for backward compatibility only. The TLS protocol is defined in IETF RFC 2246.</summary>
        Tls = 192, // 0x000000C0
        /// <summary>Specifies the TLS 1.1 security protocol. The TLS protocol is defined in IETF RFC 4346.</summary>
        Tls11 = 768, // 0x00000300
        /// <summary>Specifies the TLS 1.2 security protocol. The TLS protocol is defined in IETF RFC 5246.</summary>
        Tls12 = 3072, // 0x00000C00
        /// <summary>Specifies the TLS 1.3 security protocol. The TLS protocol is defined in IETF RFC 8446.</summary>
        Tls13 = 12288, // 0x00003000
        /// <summary>Use None instead of Default. Default permits only the Secure Sockets Layer (SSL) 3.0 or Transport Layer Security (TLS) 1.0 protocols to be negotiated, and those options are now considered obsolete. Consequently, Default is not allowed in many organizations. Despite the name of this field, <see cref="T:System.Net.Security.SslStream" /> does not use it as a default except under special circumstances.</summary>
        Default = Tls | Ssl3, // 0x000000F0
    }
    internal enum TlsCipherSuite : ushort
    {
        /// <summary>Represents the TLS_NULL_WITH_NULL_NULL cipher suite.</summary>
        TLS_NULL_WITH_NULL_NULL = 0,
        /// <summary>Represents the TLS_RSA_WITH_NULL_MD5 cipher suite.</summary>
        TLS_RSA_WITH_NULL_MD5 = 1,
        /// <summary>Represents the TLS_RSA_WITH_NULL_SHA cipher suite.</summary>
        TLS_RSA_WITH_NULL_SHA = 2,
        /// <summary>Represents the TLS_RSA_EXPORT_WITH_RC4_40_MD5 cipher suite.</summary>
        TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 3,
        /// <summary>Represents the TLS_RSA_WITH_RC4_128_MD5 cipher suite.</summary>
        TLS_RSA_WITH_RC4_128_MD5 = 4,
        /// <summary>Represents the TLS_RSA_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_RSA_WITH_RC4_128_SHA = 5,
        /// <summary>Represents the TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 cipher suite.</summary>
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 6,
        /// <summary>Represents the TLS_RSA_WITH_IDEA_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_IDEA_CBC_SHA = 7,
        /// <summary>Represents the TLS_RSA_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 8,
        /// <summary>Represents the TLS_RSA_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_DES_CBC_SHA = 9,
        /// <summary>Represents the TLS_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_3DES_EDE_CBC_SHA = 10, // 0x000A
        /// <summary>Represents the TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA = 11, // 0x000B
        /// <summary>Represents the TLS_DH_DSS_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_DES_CBC_SHA = 12, // 0x000C
        /// <summary>Represents the TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 13, // 0x000D
        /// <summary>Represents the TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA = 14, // 0x000E
        /// <summary>Represents the TLS_DH_RSA_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_DES_CBC_SHA = 15, // 0x000F
        /// <summary>Represents the TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 16, // 0x0010
        /// <summary>Represents the TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA = 17, // 0x0011
        /// <summary>Represents the TLS_DHE_DSS_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_DES_CBC_SHA = 18, // 0x0012
        /// <summary>Represents the TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 19, // 0x0013
        /// <summary>Represents the TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA = 20, // 0x0014
        /// <summary>Represents the TLS_DHE_RSA_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_DES_CBC_SHA = 21, // 0x0015
        /// <summary>Represents the TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 22, // 0x0016
        /// <summary>Represents the TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 cipher suite.</summary>
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 = 23, // 0x0017
        /// <summary>Represents the TLS_DH_anon_WITH_RC4_128_MD5 cipher suite.</summary>
        TLS_DH_anon_WITH_RC4_128_MD5 = 24, // 0x0018
        /// <summary>Represents the TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA = 25, // 0x0019
        /// <summary>Represents the TLS_DH_anon_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_DES_CBC_SHA = 26, // 0x001A
        /// <summary>Represents the TLS_DH_anon_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 27, // 0x001B
        /// <summary>Represents the TLS_KRB5_WITH_DES_CBC_SHA cipher suite.</summary>
        TLS_KRB5_WITH_DES_CBC_SHA = 30, // 0x001E
        /// <summary>Represents the TLS_KRB5_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_KRB5_WITH_3DES_EDE_CBC_SHA = 31, // 0x001F
        /// <summary>Represents the TLS_KRB5_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_KRB5_WITH_RC4_128_SHA = 32, // 0x0020
        /// <summary>Represents the TLS_KRB5_WITH_IDEA_CBC_SHA cipher suite.</summary>
        TLS_KRB5_WITH_IDEA_CBC_SHA = 33, // 0x0021
        /// <summary>Represents the TLS_KRB5_WITH_DES_CBC_MD5 cipher suite.</summary>
        TLS_KRB5_WITH_DES_CBC_MD5 = 34, // 0x0022
        /// <summary>Represents the TLS_KRB5_WITH_3DES_EDE_CBC_MD5 cipher suite.</summary>
        TLS_KRB5_WITH_3DES_EDE_CBC_MD5 = 35, // 0x0023
        /// <summary>Represents the TLS_KRB5_WITH_RC4_128_MD5 cipher suite.</summary>
        TLS_KRB5_WITH_RC4_128_MD5 = 36, // 0x0024
        /// <summary>Represents the TLS_KRB5_WITH_IDEA_CBC_MD5 cipher suite.</summary>
        TLS_KRB5_WITH_IDEA_CBC_MD5 = 37, // 0x0025
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA = 38, // 0x0026
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA = 39, // 0x0027
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_RC4_40_SHA cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_RC4_40_SHA = 40, // 0x0028
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 = 41, // 0x0029
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 = 42, // 0x002A
        /// <summary>Represents the TLS_KRB5_EXPORT_WITH_RC4_40_MD5 cipher suite.</summary>
        TLS_KRB5_EXPORT_WITH_RC4_40_MD5 = 43, // 0x002B
        /// <summary>Represents the TLS_PSK_WITH_NULL_SHA cipher suite.</summary>
        TLS_PSK_WITH_NULL_SHA = 44, // 0x002C
        /// <summary>Represents the TLS_DHE_PSK_WITH_NULL_SHA cipher suite.</summary>
        TLS_DHE_PSK_WITH_NULL_SHA = 45, // 0x002D
        /// <summary>Represents the TLS_RSA_PSK_WITH_NULL_SHA cipher suite.</summary>
        TLS_RSA_PSK_WITH_NULL_SHA = 46, // 0x002E
        /// <summary>Represents the TLS_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_AES_128_CBC_SHA = 47, // 0x002F
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_128_CBC_SHA = 48, // 0x0030
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_128_CBC_SHA = 49, // 0x0031
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 50, // 0x0032
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 51, // 0x0033
        /// <summary>Represents the TLS_DH_anon_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_AES_128_CBC_SHA = 52, // 0x0034
        /// <summary>Represents the TLS_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_AES_256_CBC_SHA = 53, // 0x0035
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_256_CBC_SHA = 54, // 0x0036
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_256_CBC_SHA = 55, // 0x0037
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 56, // 0x0038
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 57, // 0x0039
        /// <summary>Represents the TLS_DH_anon_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_AES_256_CBC_SHA = 58, // 0x003A
        /// <summary>Represents the TLS_RSA_WITH_NULL_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_NULL_SHA256 = 59, // 0x003B
        /// <summary>Represents the TLS_RSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 60, // 0x003C
        /// <summary>Represents the TLS_RSA_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 61, // 0x003D
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 62, // 0x003E
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 63, // 0x003F
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 64, // 0x0040
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA = 65, // 0x0041
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA = 66, // 0x0042
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA = 67, // 0x0043
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA = 68, // 0x0044
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA = 69, // 0x0045
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA = 70, // 0x0046
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 103, // 0x0067
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 104, // 0x0068
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 105, // 0x0069
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 106, // 0x006A
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 107, // 0x006B
        /// <summary>Represents the TLS_DH_anon_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 108, // 0x006C
        /// <summary>Represents the TLS_DH_anon_WITH_AES_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 109, // 0x006D
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 132, // 0x0084
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA = 133, // 0x0085
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA = 134, // 0x0086
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 135, // 0x0087
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 136, // 0x0088
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA = 137, // 0x0089
        /// <summary>Represents the TLS_PSK_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_PSK_WITH_RC4_128_SHA = 138, // 0x008A
        /// <summary>Represents the TLS_PSK_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_PSK_WITH_3DES_EDE_CBC_SHA = 139, // 0x008B
        /// <summary>Represents the TLS_PSK_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_PSK_WITH_AES_128_CBC_SHA = 140, // 0x008C
        /// <summary>Represents the TLS_PSK_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_PSK_WITH_AES_256_CBC_SHA = 141, // 0x008D
        /// <summary>Represents the TLS_DHE_PSK_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_DHE_PSK_WITH_RC4_128_SHA = 142, // 0x008E
        /// <summary>Represents the TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA = 143, // 0x008F
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA = 144, // 0x0090
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA = 145, // 0x0091
        /// <summary>Represents the TLS_RSA_PSK_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_RSA_PSK_WITH_RC4_128_SHA = 146, // 0x0092
        /// <summary>Represents the TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA = 147, // 0x0093
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA = 148, // 0x0094
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA = 149, // 0x0095
        /// <summary>Represents the TLS_RSA_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_RSA_WITH_SEED_CBC_SHA = 150, // 0x0096
        /// <summary>Represents the TLS_DH_DSS_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_DH_DSS_WITH_SEED_CBC_SHA = 151, // 0x0097
        /// <summary>Represents the TLS_DH_RSA_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_DH_RSA_WITH_SEED_CBC_SHA = 152, // 0x0098
        /// <summary>Represents the TLS_DHE_DSS_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_DHE_DSS_WITH_SEED_CBC_SHA = 153, // 0x0099
        /// <summary>Represents the TLS_DHE_RSA_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_DHE_RSA_WITH_SEED_CBC_SHA = 154, // 0x009A
        /// <summary>Represents the TLS_DH_anon_WITH_SEED_CBC_SHA cipher suite.</summary>
        TLS_DH_anon_WITH_SEED_CBC_SHA = 155, // 0x009B
        /// <summary>Represents the TLS_RSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_AES_128_GCM_SHA256 = 156, // 0x009C
        /// <summary>Represents the TLS_RSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_WITH_AES_256_GCM_SHA384 = 157, // 0x009D
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = 158, // 0x009E
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = 159, // 0x009F
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256 = 160, // 0x00A0
        /// <summary>Represents the TLS_DH_RSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384 = 161, // 0x00A1
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 = 162, // 0x00A2
        /// <summary>Represents the TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 = 163, // 0x00A3
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256 = 164, // 0x00A4
        /// <summary>Represents the TLS_DH_DSS_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384 = 165, // 0x00A5
        /// <summary>Represents the TLS_DH_anon_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_AES_128_GCM_SHA256 = 166, // 0x00A6
        /// <summary>Represents the TLS_DH_anon_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_anon_WITH_AES_256_GCM_SHA384 = 167, // 0x00A7
        /// <summary>Represents the TLS_PSK_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_AES_128_GCM_SHA256 = 168, // 0x00A8
        /// <summary>Represents the TLS_PSK_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_AES_256_GCM_SHA384 = 169, // 0x00A9
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 = 170, // 0x00AA
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 = 171, // 0x00AB
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 = 172, // 0x00AC
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 = 173, // 0x00AD
        /// <summary>Represents the TLS_PSK_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_AES_128_CBC_SHA256 = 174, // 0x00AE
        /// <summary>Represents the TLS_PSK_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_AES_256_CBC_SHA384 = 175, // 0x00AF
        /// <summary>Represents the TLS_PSK_WITH_NULL_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_NULL_SHA256 = 176, // 0x00B0
        /// <summary>Represents the TLS_PSK_WITH_NULL_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_NULL_SHA384 = 177, // 0x00B1
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 = 178, // 0x00B2
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 = 179, // 0x00B3
        /// <summary>Represents the TLS_DHE_PSK_WITH_NULL_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_NULL_SHA256 = 180, // 0x00B4
        /// <summary>Represents the TLS_DHE_PSK_WITH_NULL_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_NULL_SHA384 = 181, // 0x00B5
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 = 182, // 0x00B6
        /// <summary>Represents the TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 = 183, // 0x00B7
        /// <summary>Represents the TLS_RSA_PSK_WITH_NULL_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_NULL_SHA256 = 184, // 0x00B8
        /// <summary>Represents the TLS_RSA_PSK_WITH_NULL_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_NULL_SHA384 = 185, // 0x00B9
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 186, // 0x00BA
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 187, // 0x00BB
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 188, // 0x00BC
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 = 189, // 0x00BD
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 190, // 0x00BE
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 = 191, // 0x00BF
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 192, // 0x00C0
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 193, // 0x00C1
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 194, // 0x00C2
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 = 195, // 0x00C3
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 = 196, // 0x00C4
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 = 197, // 0x00C5
        /// <summary>Represents the TLS_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_AES_128_GCM_SHA256 = 4865, // 0x1301
        /// <summary>Represents the TLS_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_AES_256_GCM_SHA384 = 4866, // 0x1302
        /// <summary>Represents the TLS_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_CHACHA20_POLY1305_SHA256 = 4867, // 0x1303
        /// <summary>Represents the TLS_AES_128_CCM_SHA256 cipher suite.</summary>
        TLS_AES_128_CCM_SHA256 = 4868, // 0x1304
        /// <summary>Represents the TLS_AES_128_CCM_8_SHA256 cipher suite.</summary>
        TLS_AES_128_CCM_8_SHA256 = 4869, // 0x1305
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_NULL_SHA = 49153, // 0xC001
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA = 49154, // 0xC002
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA = 49155, // 0xC003
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA = 49156, // 0xC004
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA = 49157, // 0xC005
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_NULL_SHA = 49158, // 0xC006
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA = 49159, // 0xC007
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 49160, // 0xC008
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 49161, // 0xC009
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 49162, // 0xC00A
        /// <summary>Represents the TLS_ECDH_RSA_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDH_RSA_WITH_NULL_SHA = 49163, // 0xC00B
        /// <summary>Represents the TLS_ECDH_RSA_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDH_RSA_WITH_RC4_128_SHA = 49164, // 0xC00C
        /// <summary>Represents the TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA = 49165, // 0xC00D
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA = 49166, // 0xC00E
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 49167, // 0xC00F
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_NULL_SHA = 49168, // 0xC010
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_RC4_128_SHA = 49169, // 0xC011
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 49170, // 0xC012
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 49171, // 0xC013
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 49172, // 0xC014
        /// <summary>Represents the TLS_ECDH_anon_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDH_anon_WITH_NULL_SHA = 49173, // 0xC015
        /// <summary>Represents the TLS_ECDH_anon_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDH_anon_WITH_RC4_128_SHA = 49174, // 0xC016
        /// <summary>Represents the TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA = 49175, // 0xC017
        /// <summary>Represents the TLS_ECDH_anon_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA = 49176, // 0xC018
        /// <summary>Represents the TLS_ECDH_anon_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA = 49177, // 0xC019
        /// <summary>Represents the TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA = 49178, // 0xC01A
        /// <summary>Represents the TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA = 49179, // 0xC01B
        /// <summary>Represents the TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA = 49180, // 0xC01C
        /// <summary>Represents the TLS_SRP_SHA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA = 49181, // 0xC01D
        /// <summary>Represents the TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA = 49182, // 0xC01E
        /// <summary>Represents the TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA = 49183, // 0xC01F
        /// <summary>Represents the TLS_SRP_SHA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA = 49184, // 0xC020
        /// <summary>Represents the TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 49185, // 0xC021
        /// <summary>Represents the TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 49186, // 0xC022
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 49187, // 0xC023
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 49188, // 0xC024
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 = 49189, // 0xC025
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 = 49190, // 0xC026
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 49191, // 0xC027
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 49192, // 0xC028
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 = 49193, // 0xC029
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 = 49194, // 0xC02A
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 49195, // 0xC02B
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 49196, // 0xC02C
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 = 49197, // 0xC02D
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 = 49198, // 0xC02E
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 49199, // 0xC02F
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 49200, // 0xC030
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 = 49201, // 0xC031
        /// <summary>Represents the TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 = 49202, // 0xC032
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_RC4_128_SHA cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_RC4_128_SHA = 49203, // 0xC033
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA = 49204, // 0xC034
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA = 49205, // 0xC035
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA = 49206, // 0xC036
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 49207, // 0xC037
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 = 49208, // 0xC038
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_NULL_SHA cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_NULL_SHA = 49209, // 0xC039
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_NULL_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_NULL_SHA256 = 49210, // 0xC03A
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_NULL_SHA384 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_NULL_SHA384 = 49211, // 0xC03B
        /// <summary>Represents the TLS_RSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_ARIA_128_CBC_SHA256 = 49212, // 0xC03C
        /// <summary>Represents the TLS_RSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_RSA_WITH_ARIA_256_CBC_SHA384 = 49213, // 0xC03D
        /// <summary>Represents the TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 = 49214, // 0xC03E
        /// <summary>Represents the TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 = 49215, // 0xC03F
        /// <summary>Represents the TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 = 49216, // 0xC040
        /// <summary>Represents the TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 = 49217, // 0xC041
        /// <summary>Represents the TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 = 49218, // 0xC042
        /// <summary>Represents the TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 = 49219, // 0xC043
        /// <summary>Represents the TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 = 49220, // 0xC044
        /// <summary>Represents the TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 = 49221, // 0xC045
        /// <summary>Represents the TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 = 49222, // 0xC046
        /// <summary>Represents the TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 = 49223, // 0xC047
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 = 49224, // 0xC048
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 = 49225, // 0xC049
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 = 49226, // 0xC04A
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 = 49227, // 0xC04B
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 = 49228, // 0xC04C
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 = 49229, // 0xC04D
        /// <summary>Represents the TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 = 49230, // 0xC04E
        /// <summary>Represents the TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 = 49231, // 0xC04F
        /// <summary>Represents the TLS_RSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_ARIA_128_GCM_SHA256 = 49232, // 0xC050
        /// <summary>Represents the TLS_RSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_WITH_ARIA_256_GCM_SHA384 = 49233, // 0xC051
        /// <summary>Represents the TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 = 49234, // 0xC052
        /// <summary>Represents the TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 = 49235, // 0xC053
        /// <summary>Represents the TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 = 49236, // 0xC054
        /// <summary>Represents the TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 = 49237, // 0xC055
        /// <summary>Represents the TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 = 49238, // 0xC056
        /// <summary>Represents the TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 = 49239, // 0xC057
        /// <summary>Represents the TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 = 49240, // 0xC058
        /// <summary>Represents the TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 = 49241, // 0xC059
        /// <summary>Represents the TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 = 49242, // 0xC05A
        /// <summary>Represents the TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 = 49243, // 0xC05B
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 = 49244, // 0xC05C
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 = 49245, // 0xC05D
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 = 49246, // 0xC05E
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 = 49247, // 0xC05F
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 = 49248, // 0xC060
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 = 49249, // 0xC061
        /// <summary>Represents the TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 = 49250, // 0xC062
        /// <summary>Represents the TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 = 49251, // 0xC063
        /// <summary>Represents the TLS_PSK_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_ARIA_128_CBC_SHA256 = 49252, // 0xC064
        /// <summary>Represents the TLS_PSK_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_ARIA_256_CBC_SHA384 = 49253, // 0xC065
        /// <summary>Represents the TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 = 49254, // 0xC066
        /// <summary>Represents the TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 = 49255, // 0xC067
        /// <summary>Represents the TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 = 49256, // 0xC068
        /// <summary>Represents the TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 = 49257, // 0xC069
        /// <summary>Represents the TLS_PSK_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_ARIA_128_GCM_SHA256 = 49258, // 0xC06A
        /// <summary>Represents the TLS_PSK_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_ARIA_256_GCM_SHA384 = 49259, // 0xC06B
        /// <summary>Represents the TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 = 49260, // 0xC06C
        /// <summary>Represents the TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 = 49261, // 0xC06D
        /// <summary>Represents the TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 = 49262, // 0xC06E
        /// <summary>Represents the TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 = 49263, // 0xC06F
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 = 49264, // 0xC070
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 = 49265, // 0xC071
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 49266, // 0xC072
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 49267, // 0xC073
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = 49268, // 0xC074
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = 49269, // 0xC075
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 49270, // 0xC076
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 49271, // 0xC077
        /// <summary>Represents the TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 = 49272, // 0xC078
        /// <summary>Represents the TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 = 49273, // 0xC079
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 49274, // 0xC07A
        /// <summary>Represents the TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 49275, // 0xC07B
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 49276, // 0xC07C
        /// <summary>Represents the TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 49277, // 0xC07D
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 49278, // 0xC07E
        /// <summary>Represents the TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 49279, // 0xC07F
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 49280, // 0xC080
        /// <summary>Represents the TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 49281, // 0xC081
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 = 49282, // 0xC082
        /// <summary>Represents the TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 = 49283, // 0xC083
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 = 49284, // 0xC084
        /// <summary>Represents the TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 = 49285, // 0xC085
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 49286, // 0xC086
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 49287, // 0xC087
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 = 49288, // 0xC088
        /// <summary>Represents the TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 = 49289, // 0xC089
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 49290, // 0xC08A
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 49291, // 0xC08B
        /// <summary>Represents the TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 = 49292, // 0xC08C
        /// <summary>Represents the TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 = 49293, // 0xC08D
        /// <summary>Represents the TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 49294, // 0xC08E
        /// <summary>Represents the TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 49295, // 0xC08F
        /// <summary>Represents the TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 49296, // 0xC090
        /// <summary>Represents the TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 49297, // 0xC091
        /// <summary>Represents the TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 = 49298, // 0xC092
        /// <summary>Represents the TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 = 49299, // 0xC093
        /// <summary>Represents the TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 49300, // 0xC094
        /// <summary>Represents the TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 49301, // 0xC095
        /// <summary>Represents the TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 49302, // 0xC096
        /// <summary>Represents the TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 49303, // 0xC097
        /// <summary>Represents the TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 49304, // 0xC098
        /// <summary>Represents the TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 49305, // 0xC099
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 = 49306, // 0xC09A
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 = 49307, // 0xC09B
        /// <summary>Represents the TLS_RSA_WITH_AES_128_CCM cipher suite.</summary>
        TLS_RSA_WITH_AES_128_CCM = 49308, // 0xC09C
        /// <summary>Represents the TLS_RSA_WITH_AES_256_CCM cipher suite.</summary>
        TLS_RSA_WITH_AES_256_CCM = 49309, // 0xC09D
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_128_CCM cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_128_CCM = 49310, // 0xC09E
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_256_CCM cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_256_CCM = 49311, // 0xC09F
        /// <summary>Represents the TLS_RSA_WITH_AES_128_CCM_8 cipher suite.</summary>
        TLS_RSA_WITH_AES_128_CCM_8 = 49312, // 0xC0A0
        /// <summary>Represents the TLS_RSA_WITH_AES_256_CCM_8 cipher suite.</summary>
        TLS_RSA_WITH_AES_256_CCM_8 = 49313, // 0xC0A1
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_128_CCM_8 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_128_CCM_8 = 49314, // 0xC0A2
        /// <summary>Represents the TLS_DHE_RSA_WITH_AES_256_CCM_8 cipher suite.</summary>
        TLS_DHE_RSA_WITH_AES_256_CCM_8 = 49315, // 0xC0A3
        /// <summary>Represents the TLS_PSK_WITH_AES_128_CCM cipher suite.</summary>
        TLS_PSK_WITH_AES_128_CCM = 49316, // 0xC0A4
        /// <summary>Represents the TLS_PSK_WITH_AES_256_CCM cipher suite.</summary>
        TLS_PSK_WITH_AES_256_CCM = 49317, // 0xC0A5
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_128_CCM cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_128_CCM = 49318, // 0xC0A6
        /// <summary>Represents the TLS_DHE_PSK_WITH_AES_256_CCM cipher suite.</summary>
        TLS_DHE_PSK_WITH_AES_256_CCM = 49319, // 0xC0A7
        /// <summary>Represents the TLS_PSK_WITH_AES_128_CCM_8 cipher suite.</summary>
        TLS_PSK_WITH_AES_128_CCM_8 = 49320, // 0xC0A8
        /// <summary>Represents the TLS_PSK_WITH_AES_256_CCM_8 cipher suite.</summary>
        TLS_PSK_WITH_AES_256_CCM_8 = 49321, // 0xC0A9
        /// <summary>Represents the TLS_PSK_DHE_WITH_AES_128_CCM_8 cipher suite.</summary>
        TLS_PSK_DHE_WITH_AES_128_CCM_8 = 49322, // 0xC0AA
        /// <summary>Represents the TLS_PSK_DHE_WITH_AES_256_CCM_8 cipher suite.</summary>
        TLS_PSK_DHE_WITH_AES_256_CCM_8 = 49323, // 0xC0AB
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_128_CCM cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 49324, // 0xC0AC
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_256_CCM cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 49325, // 0xC0AD
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 49326, // 0xC0AE
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 49327, // 0xC0AF
        /// <summary>Represents the TLS_ECCPWD_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECCPWD_WITH_AES_128_GCM_SHA256 = 49328, // 0xC0B0
        /// <summary>Represents the TLS_ECCPWD_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECCPWD_WITH_AES_256_GCM_SHA384 = 49329, // 0xC0B1
        /// <summary>Represents the TLS_ECCPWD_WITH_AES_128_CCM_SHA256 cipher suite.</summary>
        TLS_ECCPWD_WITH_AES_128_CCM_SHA256 = 49330, // 0xC0B2
        /// <summary>Represents the TLS_ECCPWD_WITH_AES_256_CCM_SHA384 cipher suite.</summary>
        TLS_ECCPWD_WITH_AES_256_CCM_SHA384 = 49331, // 0xC0B3
        /// <summary>Represents the TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52392, // 0xCCA8
        /// <summary>Represents the TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 52393, // 0xCCA9
        /// <summary>Represents the TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 52394, // 0xCCAA
        /// <summary>Represents the TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52395, // 0xCCAB
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52396, // 0xCCAC
        /// <summary>Represents the TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52397, // 0xCCAD
        /// <summary>Represents the TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 cipher suite.</summary>
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 = 52398, // 0xCCAE
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 = 53249, // 0xD001
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 = 53250, // 0xD002
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 = 53251, // 0xD003
        /// <summary>Represents the TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 cipher suite.</summary>
        TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 = 53253, // 0xD005
    }
}