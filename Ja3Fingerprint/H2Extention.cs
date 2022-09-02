//-----------------------------------------------------------------------
// <copyright file="H2Extention .cs" company="Company">
// Copyright (C) Company. All Rights Reserved.
// </copyright>
// <author>nainaigu</author>
// <create>$Date$</create>
// <summary></summary>
//-----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;

namespace Ja3Fingerprint
{
    internal static class H2Extention
    {
        public static async Task ProcessH2Async(ConnectionContext connectionContext)
        {
            var input = connectionContext.Transport.Input;
            ReadResult readResult = await input.ReadAsync();
            try
            {
                if (!H2Extention.TryReadPreface(readResult, out var consumed, out var examined))
                {
                    return;
                }

                input.AdvanceTo(consumed, examined);

                ReadResult result = await input.ReadAsync();
                ReadOnlySequence<byte> buffer = result.Buffer;

                ReadOnlySequence<byte> payload;
                var _incomingFrame = new Http2Frame();
                var h2Sig = "";

                while (H2Extention.TryReadFrame(ref buffer, _incomingFrame, 16384, out payload))
                {

                    var data = H2Extention.ProcessFrameAsync(_incomingFrame, payload);
                    if (data != null)
                    {
#if DEBUG
                        Console.WriteLine("StreamId:" + _incomingFrame.StreamId + "->" + _incomingFrame + "->" + data);
#endif
                        h2Sig += "^" + (_incomingFrame.Type) + "->" + data;
                    }

                }
                if (!string.IsNullOrEmpty(h2Sig))
                {
                    connectionContext.ConnectionId += "@" + h2Sig;

                }

                // input.AdvanceTo(buffer.Start, buffer.End);
                // header读取
                // ReadResult result2 = await input.ReadAsync();
                // ReadOnlySequence<byte> buffer2 = result2.Buffer;
            }
            catch (Exception e)
            {
                //ignore
            }
            finally
            {
                var examined2 = readResult.Buffer.Slice(readResult.Buffer.Start, 0).End;
                input.AdvanceTo(readResult.Buffer.Start, examined2);
            }
        }



        public static bool TryReadPreface(ReadResult readResult, out SequencePosition consumed, out SequencePosition examined)
        {

            ReadOnlySequence<byte> buffer = readResult.Buffer;
            consumed = buffer.Start;
            examined = buffer.End;
            if (!buffer.IsEmpty && ParsePreface(in buffer, out consumed, out examined))
                return true;
            if (readResult.IsCompleted)
                return false;
            return false;
        }

        public static bool ParsePreface(
            in ReadOnlySequence<byte> buffer,
            out SequencePosition consumed,
            out SequencePosition examined)
        {
            consumed = buffer.Start;
            examined = buffer.End;
            if (buffer.Length < (long)24)
                return false;
            ReadOnlySequence<byte> buffer1 = buffer.Slice(0, 24);
            consumed = examined = buffer1.End;
            return true;
        }

        public static object ProcessFrameAsync(Http2Frame _incomingFrame, ReadOnlySequence<byte> payload)
        {
            switch (_incomingFrame.Type)
            {
                case Http2FrameType.SETTINGS:
                    Http2PeerSettings settings = new Http2PeerSettings();
                    var http2PeerSettings = ReadSettings(payload);
                    settings.Update(http2PeerSettings);
                    return settings;
                case Http2FrameType.WINDOW_UPDATE:
                    return _incomingFrame.WindowUpdateSizeIncrement;
                    break;
                default:
                    break;
            }

            return null;
        }


        public static IList<Http2PeerSetting> ReadSettings(
            in ReadOnlySequence<byte> payload)
        {
            ReadOnlySpan<byte> payload1 = payload.ToSpan();
            Http2PeerSetting[] http2PeerSettingArray = new Http2PeerSetting[payload1.Length / 6];
            for (int index = 0; index < http2PeerSettingArray.Length; ++index)
            {
                http2PeerSettingArray[index] = ReadSetting(payload1);
                payload1 = payload1.Slice(6);
            }
            return (IList<Http2PeerSetting>)http2PeerSettingArray;
        }
        private static Http2PeerSetting ReadSetting(ReadOnlySpan<byte> payload) => new Http2PeerSetting((Http2SettingsParameter)BinaryPrimitives.ReadUInt16BigEndian(payload), BinaryPrimitives.ReadUInt32BigEndian(payload.Slice(2)));
        public static bool TryReadFrame(
            ref ReadOnlySequence<byte> buffer,
            Http2Frame frame,
            uint maxFrameSize,
            out ReadOnlySequence<byte> framePayload)
        {
            framePayload = ReadOnlySequence<byte>.Empty;
            if (buffer.Length < 9L)
                return false;
            ReadOnlySequence<byte> buffer1 = buffer.Slice(0, 9);
            ReadOnlySpan<byte> span = buffer1.ToSpan();
            int size = (int)ReadUInt24BigEndian(span);
            if ((long)size > (long)maxFrameSize)
                throw new Exception("parse h2 error");
            int num1 = 9 + size;
            if (buffer.Length < (long)num1)
                return false;
            frame.PayloadLength = size;
            frame.Type = (Http2FrameType)span[3];
            frame.Flags = span[4];
            frame.StreamId = (int)ReadUInt31BigEndian(span.Slice(5));
            int num2 = ReadExtendedFields(frame, in buffer);
            framePayload = buffer.Slice(9 + num2, size - num2);
            buffer = buffer.Slice(framePayload.End);
            return true;
        }


        private static int ReadExtendedFields(
            Http2Frame frame,
            in ReadOnlySequence<byte> readableBuffer)
        {
            int payloadFieldsLength = GetPayloadFieldsLength(frame);
            if (payloadFieldsLength > frame.PayloadLength)
                throw new Exception("FRAME_SIZE_ERROR");
            ReadOnlySequence<byte> buffer = readableBuffer.Slice(9, payloadFieldsLength);
            ReadOnlySpan<byte> source = buffer.ToSpan();
            switch (frame.Type)
            {
                case Http2FrameType.DATA:
                    frame.DataPadLength = frame.DataHasPadding ? source[0] : (byte)0;
                    break;
                case Http2FrameType.HEADERS:
                    if (frame.HeadersHasPadding)
                    {
                        frame.HeadersPadLength = source[0];
                        source = source.Slice(1);
                    }
                    else
                        frame.HeadersPadLength = (byte)0;

                    if (frame.HeadersHasPriority)
                    {
                        frame.HeadersStreamDependency = (int)ReadUInt31BigEndian(source);
                        frame.HeadersPriorityWeight = source.Slice(4)[0];
                        break;
                    }

                    frame.HeadersStreamDependency = 0;
                    frame.HeadersPriorityWeight = (byte)0;
                    break;
                case Http2FrameType.PRIORITY:
                    frame.PriorityStreamDependency = (int)ReadUInt31BigEndian(source);
                    frame.PriorityWeight = source.Slice(4)[0];
                    break;
                case Http2FrameType.RST_STREAM:
                    frame.RstStreamErrorCode = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(source);
                    break;
                case Http2FrameType.GOAWAY:
                    frame.GoAwayLastStreamId = (int)ReadUInt31BigEndian(source);
                    frame.GoAwayErrorCode = (Http2ErrorCode)BinaryPrimitives.ReadUInt32BigEndian(source.Slice(4));
                    break;
                case Http2FrameType.WINDOW_UPDATE:
                    frame.WindowUpdateSizeIncrement = (int)ReadUInt31BigEndian(source);
                    break;
                default:
                    return 0;
            }

            return payloadFieldsLength;
        }

        public static int GetPayloadFieldsLength(Http2Frame frame)
        {
            switch (frame.Type)
            {
                case Http2FrameType.DATA:
                    return !frame.DataHasPadding ? 0 : 1;
                case Http2FrameType.HEADERS:
                    return (frame.HeadersHasPadding ? 1 : 0) + (frame.HeadersHasPriority ? 5 : 0);
                case Http2FrameType.PRIORITY:
                    return 5;
                case Http2FrameType.RST_STREAM:
                    return 4;
                case Http2FrameType.GOAWAY:
                    return 8;
                case Http2FrameType.WINDOW_UPDATE:
                    return 4;
                default:
                    return 0;
            }
        }

        public static ReadOnlySpan<byte> ToSpan(in this ReadOnlySequence<byte> buffer) =>
            buffer.IsSingleSegment ? buffer.FirstSpan : (ReadOnlySpan<byte>)buffer.ToArray<byte>();

        public static uint ReadUInt24BigEndian(ReadOnlySpan<byte> source) => (uint)((int)source[0] << 16 | (int)source[1] << 8) | (uint)source[2];
        public static uint ReadUInt31BigEndian(ReadOnlySpan<byte> source) => ReadUInt32BigEndian(source) & (uint)int.MaxValue;

        public static uint ReadUInt32BigEndian(ReadOnlySpan<byte> source)
        {
            uint num = MemoryMarshal.Read<uint>(source);
            if (BitConverter.IsLittleEndian)
                num = BinaryPrimitives.ReverseEndianness(num);
            return num;
        }
    }

    internal enum Http2FrameType : byte
    {
        DATA,
        HEADERS,
        PRIORITY,
        RST_STREAM,
        SETTINGS,
        PUSH_PROMISE,
        PING,
        GOAWAY,
        WINDOW_UPDATE,
        CONTINUATION,
    }

    internal class Http2Frame
    {
        public Http2ContinuationFrameFlags ContinuationFlags
        {
            get => (Http2ContinuationFrameFlags)this.Flags;
            set => this.Flags = (byte)value;
        }

        public bool ContinuationEndHeaders => (this.ContinuationFlags & Http2ContinuationFrameFlags.END_HEADERS) == Http2ContinuationFrameFlags.END_HEADERS;

        public void PrepareContinuation(Http2ContinuationFrameFlags flags, int streamId)
        {
            this.PayloadLength = 0;
            this.Type = Http2FrameType.CONTINUATION;
            this.ContinuationFlags = flags;
            this.StreamId = streamId;
        }

        public int PayloadLength { get; set; }

        public Http2FrameType Type { get; set; }

        public byte Flags { get; set; }

        public int StreamId { get; set; }

        internal object ShowFlags()
        {
            return (object)string.Format("0x{0:x}", (object)this.Flags);
            // switch (this.Type)
            // {
            //     case Http2FrameType.DATA:
            //         return (object)this.DataFlags;
            //     case Http2FrameType.HEADERS:
            //         return (object)this.HeadersFlags;
            //     case Http2FrameType.SETTINGS:
            //         return (object)this.SettingsFlags;
            //     case Http2FrameType.PING:
            //         return (object)this.PingFlags;
            //     case Http2FrameType.CONTINUATION:
            //         return (object)this.ContinuationFlags;
            //     default:
            //         
            // }
        }

        public override string ToString() => string.Format("{0} Stream: {1} Length: {2} Flags: {3}", (object)this.Type, (object)this.StreamId,
            (object)this.PayloadLength, this.ShowFlags());

        public Http2DataFrameFlags DataFlags
        {
            get => (Http2DataFrameFlags)this.Flags;
            set => this.Flags = (byte)value;
        }

        public bool DataEndStream => (this.DataFlags & Http2DataFrameFlags.END_STREAM) == Http2DataFrameFlags.END_STREAM;

        public bool DataHasPadding => (this.DataFlags & Http2DataFrameFlags.PADDED) == Http2DataFrameFlags.PADDED;

        public byte DataPadLength { get; set; }

        private int DataPayloadOffset => !this.DataHasPadding ? 0 : 1;

        public int DataPayloadLength => this.PayloadLength - this.DataPayloadOffset - (int)this.DataPadLength;

        public void PrepareData(int streamId, byte? padLength = null)
        {
            this.PayloadLength = 0;
            this.Type = Http2FrameType.DATA;
            this.DataFlags = padLength.HasValue ? Http2DataFrameFlags.PADDED : Http2DataFrameFlags.NONE;
            this.StreamId = streamId;
            this.DataPadLength = padLength.GetValueOrDefault();
        }

        public int GoAwayLastStreamId { get; set; }

        public Http2ErrorCode GoAwayErrorCode { get; set; }

        public void PrepareGoAway(int lastStreamId, Http2ErrorCode errorCode)
        {
            this.PayloadLength = 8;
            this.Type = Http2FrameType.GOAWAY;
            this.Flags = (byte)0;
            this.StreamId = 0;
            this.GoAwayLastStreamId = lastStreamId;
            this.GoAwayErrorCode = errorCode;
        }

        public Http2HeadersFrameFlags HeadersFlags
        {
            get => (Http2HeadersFrameFlags)this.Flags;
            set => this.Flags = (byte)value;
        }

        public bool HeadersEndHeaders => (this.HeadersFlags & Http2HeadersFrameFlags.END_HEADERS) == Http2HeadersFrameFlags.END_HEADERS;

        public bool HeadersEndStream => (this.HeadersFlags & Http2HeadersFrameFlags.END_STREAM) == Http2HeadersFrameFlags.END_STREAM;

        public bool HeadersHasPadding => (this.HeadersFlags & Http2HeadersFrameFlags.PADDED) == Http2HeadersFrameFlags.PADDED;

        public bool HeadersHasPriority => (this.HeadersFlags & Http2HeadersFrameFlags.PRIORITY) == Http2HeadersFrameFlags.PRIORITY;

        public byte HeadersPadLength { get; set; }

        public int HeadersStreamDependency { get; set; }

        public byte HeadersPriorityWeight { get; set; }

        private int HeadersPayloadOffset => (this.HeadersHasPadding ? 1 : 0) + (this.HeadersHasPriority ? 5 : 0);

        public int HeadersPayloadLength => this.PayloadLength - this.HeadersPayloadOffset - (int)this.HeadersPadLength;

        public void PrepareHeaders(Http2HeadersFrameFlags flags, int streamId)
        {
            this.PayloadLength = 0;
            this.Type = Http2FrameType.HEADERS;
            this.HeadersFlags = flags;
            this.StreamId = streamId;
        }

        public Http2PingFrameFlags PingFlags
        {
            get => (Http2PingFrameFlags)this.Flags;
            set => this.Flags = (byte)value;
        }

        public bool PingAck => (this.PingFlags & Http2PingFrameFlags.ACK) == Http2PingFrameFlags.ACK;

        public void PreparePing(Http2PingFrameFlags flags)
        {
            this.PayloadLength = 8;
            this.Type = Http2FrameType.PING;
            this.PingFlags = flags;
            this.StreamId = 0;
        }

        public int PriorityStreamDependency { get; set; }

        public bool PriorityIsExclusive { get; set; }

        public byte PriorityWeight { get; set; }

        public void PreparePriority(int streamId, int streamDependency, bool exclusive, byte weight)
        {
            this.PayloadLength = 5;
            this.Type = Http2FrameType.PRIORITY;
            this.StreamId = streamId;
            this.PriorityStreamDependency = streamDependency;
            this.PriorityIsExclusive = exclusive;
            this.PriorityWeight = weight;
        }

        public Http2ErrorCode RstStreamErrorCode { get; set; }

        public void PrepareRstStream(int streamId, Http2ErrorCode errorCode)
        {
            this.PayloadLength = 4;
            this.Type = Http2FrameType.RST_STREAM;
            this.Flags = (byte)0;
            this.StreamId = streamId;
            this.RstStreamErrorCode = errorCode;
        }

        public Http2SettingsFrameFlags SettingsFlags
        {
            get => (Http2SettingsFrameFlags)this.Flags;
            set => this.Flags = (byte)value;
        }

        public bool SettingsAck => (this.SettingsFlags & Http2SettingsFrameFlags.ACK) == Http2SettingsFrameFlags.ACK;

        public void PrepareSettings(Http2SettingsFrameFlags flags)
        {
            this.PayloadLength = 0;
            this.Type = Http2FrameType.SETTINGS;
            this.SettingsFlags = flags;
            this.StreamId = 0;
        }

        public int WindowUpdateSizeIncrement { get; set; }

        public void PrepareWindowUpdate(int streamId, int sizeIncrement)
        {
            this.PayloadLength = 4;
            this.Type = Http2FrameType.WINDOW_UPDATE;
            this.Flags = (byte)0;
            this.StreamId = streamId;
            this.WindowUpdateSizeIncrement = sizeIncrement;
        }
    }

    internal enum Http2ErrorCode : uint
    {
        NO_ERROR,
        PROTOCOL_ERROR,
        INTERNAL_ERROR,
        FLOW_CONTROL_ERROR,
        SETTINGS_TIMEOUT,
        STREAM_CLOSED,
        FRAME_SIZE_ERROR,
        REFUSED_STREAM,
        CANCEL,
        COMPRESSION_ERROR,
        CONNECT_ERROR,
        ENHANCE_YOUR_CALM,
        INADEQUATE_SECURITY,
        HTTP_1_1_REQUIRED,
    }

    [Flags]
    internal enum Http2PingFrameFlags : byte
    {
        NONE = 0,
        ACK = 1,
    }

    [Flags]
    internal enum Http2ContinuationFrameFlags : byte
    {
        NONE = 0,
        END_HEADERS = 4,
    }

    [Flags]
    internal enum Http2DataFrameFlags : byte
    {
        NONE = 0,
        END_STREAM = 1,
        PADDED = 8,
    }

    [Flags]
    internal enum Http2SettingsFrameFlags : byte
    {
        NONE = 0,
        ACK = 1,
    }

    [Flags]
    internal enum Http2HeadersFrameFlags : byte
    {
        NONE = 0,
        END_STREAM = 1,
        END_HEADERS = 4,
        PADDED = 8,
        PRIORITY = 32, // 0x20
    }
    internal readonly struct Http2PeerSetting
    {
        public Http2PeerSetting(Http2SettingsParameter parameter, uint value)
        {
            this.Parameter = parameter;
            this.Value = value;
        }

        public Http2SettingsParameter Parameter { get; }

        public uint Value { get; }
    }
    internal enum Http2SettingsParameter : ushort
    {
        SETTINGS_HEADER_TABLE_SIZE = 1,
        SETTINGS_ENABLE_PUSH = 2,
        SETTINGS_MAX_CONCURRENT_STREAMS = 3,
        SETTINGS_INITIAL_WINDOW_SIZE = 4,
        SETTINGS_MAX_FRAME_SIZE = 5,
        SETTINGS_MAX_HEADER_LIST_SIZE = 6,
    }
    internal class Http2PeerSettings
    {
        public const uint DefaultHeaderTableSize = 4096;
        public const bool DefaultEnablePush = true;
        public const uint DefaultMaxConcurrentStreams = 4294967295;
        public const uint DefaultInitialWindowSize = 65535;
        public const uint DefaultMaxFrameSize = 16384;
        public const uint DefaultMaxHeaderListSize = 4294967295;
        public const uint MaxWindowSize = 2147483647;
        internal const int MinAllowedMaxFrameSize = 16384;
        internal const int MaxAllowedMaxFrameSize = 16777215;

        public uint HeaderTableSize { get; set; } = 4096;

        public bool EnablePush { get; set; } = true;

        public uint MaxConcurrentStreams { get; set; } = uint.MaxValue;

        public uint InitialWindowSize { get; set; } = (uint)ushort.MaxValue;

        public uint MaxFrameSize { get; set; } = 16384;

        public uint MaxHeaderListSize { get; set; } = uint.MaxValue;

        public Dictionary<int, uint> allData = new Dictionary<int, uint>();

        public void Update(IList<Http2PeerSetting> settings)
        {
            foreach (Http2PeerSetting setting in (IEnumerable<Http2PeerSetting>)settings)
            {
                uint num = setting.Value;
                switch (setting.Parameter)
                {
                    case Http2SettingsParameter.SETTINGS_HEADER_TABLE_SIZE:
                        this.HeaderTableSize = num;
                        allData.Add((int)Http2SettingsParameter.SETTINGS_HEADER_TABLE_SIZE, num);
                        continue;
                    case Http2SettingsParameter.SETTINGS_ENABLE_PUSH:
                        if (num != 0U && num != 1U)
                            throw new Exception("Http2SettingsParameter.SETTINGS_ENABLE_PUSH");
                        this.EnablePush = num == 1U;
                        allData.Add((int)Http2SettingsParameter.SETTINGS_ENABLE_PUSH, num);
                        continue;
                    case Http2SettingsParameter.SETTINGS_MAX_CONCURRENT_STREAMS:
                        this.MaxConcurrentStreams = num;
                        allData.Add((int)Http2SettingsParameter.SETTINGS_MAX_CONCURRENT_STREAMS, num);
                        continue;
                    case Http2SettingsParameter.SETTINGS_INITIAL_WINDOW_SIZE:
                        this.InitialWindowSize = num <= (uint)int.MaxValue ? num : throw new Exception("Http2SettingsParameter.SETTINGS_INITIAL_WINDOW_SIZE");
                        allData.Add((int)Http2SettingsParameter.SETTINGS_INITIAL_WINDOW_SIZE, num);
                        continue;
                    case Http2SettingsParameter.SETTINGS_MAX_FRAME_SIZE:
                        this.MaxFrameSize = num >= 16384U && num <= 16777215U ? num : throw new Exception("Http2SettingsParameter.SETTINGS_MAX_FRAME_SIZE");
                        allData.Add((int)Http2SettingsParameter.SETTINGS_MAX_FRAME_SIZE, num);
                        continue;
                    case Http2SettingsParameter.SETTINGS_MAX_HEADER_LIST_SIZE:
                        this.MaxHeaderListSize = num;
                        allData.Add((int)Http2SettingsParameter.SETTINGS_MAX_HEADER_LIST_SIZE, num);
                        continue;
                    default:
                        continue;
                }
            }
        }

        public override string ToString()
        {
            return JsonSerializer.Serialize(allData);
        }
    }
}