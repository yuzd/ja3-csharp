using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Connections;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Core.Features;
using Microsoft.Extensions.Logging;

namespace ja3Csharp
{
    public static class TlsFilterConnectionMiddlewareExtensions
    {
        public static IConnectionBuilder UseTlsFilter(
            this IConnectionBuilder builder)
        {
            return builder.Use((connection, next) =>
            {
                var tlsFeature = connection.Features.Get<ITlsHandshakeFeature>();

                Console.WriteLine("TlsHandshake=>" + JsonSerializer.Serialize(tlsFeature));

                if (tlsFeature.CipherAlgorithm == CipherAlgorithmType.Null)
                {
                    throw new NotSupportedException("Prohibited cipher: " +
                                                    tlsFeature.CipherAlgorithm);
                }

                return next();
            });
        }


        public static async Task ProcessH2Async(ConnectionContext connectionContext, ILogger<Program> logger)
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

                bool frameReceived = false;
                ReadOnlySequence<byte> payload;
                var _incomingFrame = new Http2Frame();
                var h2Sig = "";

                while (H2Extention.TryReadFrame(ref buffer, _incomingFrame, 16384, out payload))
                {
                    frameReceived = true;

                    var data = H2Extention.ProcessFrameAsync(_incomingFrame, payload);
                    if (data != null)
                    {
                        Console.WriteLine("StreamId:" + _incomingFrame.StreamId + "->" + _incomingFrame + "->" + data);
                        h2Sig += "^" + (_incomingFrame.Type)+"->"+data;
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
                Console.WriteLine(e);
                throw;
            }
            finally
            {
                var examined2 = readResult.Buffer.Slice(readResult.Buffer.Start, 0).End;
                input.AdvanceTo(readResult.Buffer.Start, examined2);
            }
        }

        private static bool TryReadHttp2(ConnectionContext connectionContext, ReadOnlySequence<byte> buffer, ILogger logger, out bool abort)
        {
            abort = false;


            return true;
        }

        public static async Task ProcessAsync(ConnectionContext connectionContext, Func<Task> next, ILogger<Program> logger)
        {
            var input = connectionContext.Transport.Input;
            // Count how many bytes we've examined so we never go backwards, Pipes don't allow that.
            var minBytesExamined = 0L;
            while (true)
            {
                var result = await input.ReadAsync();
                var buffer = result.Buffer;

                if (result.IsCompleted)
                {
                    return;
                }

                if (buffer.Length == 0)
                {
                    continue;
                }

                if (!TryReadHello(connectionContext, buffer, logger, out var abort))
                {
                    minBytesExamined = buffer.Length;
                    input.AdvanceTo(buffer.Start, buffer.End);
                    continue;
                }

                var examined = buffer.Slice(buffer.Start, minBytesExamined).End;
                input.AdvanceTo(buffer.Start, examined);

                if (abort)
                {
                    // Close the connection.
                    return;
                }

                break;
            }

            await next();
        }

        private static bool TryReadHello(ConnectionContext connectionContext, ReadOnlySequence<byte> buffer, ILogger logger, out bool abort)
        {
            abort = false;

            if (!buffer.IsSingleSegment)
            {
                throw new NotImplementedException("Multiple buffer segments");
            }

            var data = buffer.First.Span;

            TlsFrameHelper.TlsFrameInfo info = default;
            if (!TlsFrameHelper.TryGetFrameInfo(data, ref info))
            {
                return false;
            }

            //if (!info.SupportedVersions.HasFlag(System.Security.Authentication.SslProtocols.Tls12))
            //{
            //    logger.LogInformation("Unsupported versions: {versions}", info.SupportedVersions);
            //    abort = true;
            //}
            //else
            //{
            //    logger.LogInformation("Protocol versions: {versions}", info.SupportedVersions);
            //}

            //if (!AllowHost(info.TargetName))
            //{
            //    logger.LogInformation("Disallowed host: {host}", info.TargetName);
            //    abort = true;
            //}
            //else
            //{
            //    logger.LogInformation("SNI: {host}", info.TargetName);
            //}

            var valueTuple = info.getSig();
            Console.WriteLine("指纹:" + valueTuple.Item1 + Environment.NewLine + "Md5:" + valueTuple.Item2);
            connectionContext.ConnectionId += "@" + (valueTuple.Item1 + "@" + valueTuple.Item2 + "@" + valueTuple.Item3);
            return true;
        }


        private static bool AllowHost(string targetName)
        {
            //if (string.Equals("localhost", targetName, StringComparison.OrdinalIgnoreCase))
            //{
            //    return true;
            //}
            return true;
        }
    }
}