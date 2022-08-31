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
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;

namespace ja3Csharp
{
    internal static class H2Extention
    {
        public static  bool TryReadPreface(ReadResult readResult,out SequencePosition consumed,out SequencePosition examined)
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
            switch (this.Type)
            {
                case Http2FrameType.DATA:
                    return (object)this.DataFlags;
                case Http2FrameType.HEADERS:
                    return (object)this.HeadersFlags;
                case Http2FrameType.SETTINGS:
                    return (object)this.SettingsFlags;
                case Http2FrameType.PING:
                    return (object)this.PingFlags;
                case Http2FrameType.CONTINUATION:
                    return (object)this.ContinuationFlags;
                default:
                    return (object)string.Format("0x{0:x}", (object)this.Flags);
            }
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
}