using System;
using System.Buffers;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;

namespace Ja3Fingerprint
{
    internal static class TlsFilterConnectionMiddlewareExtensions
    {

        public static async Task ProcessAsync(ConnectionContext connectionContext, Func<Task> next)
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

                if (!TryReadHello(connectionContext, buffer, out var abort))
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

        private static bool TryReadHello(ConnectionContext connectionContext, ReadOnlySequence<byte> buffer, out bool abort)
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


            var valueTuple = info.getSig();
#if DEBUG
            Console.WriteLine("指纹:" + valueTuple.Item1 + Environment.NewLine + "Md5:" + valueTuple.Item2);
#endif
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