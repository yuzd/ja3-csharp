using System.Buffers;
using System.IO.Pipelines;
using System.Text;
using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;

namespace ssltest
{
    public class MyTCPConnectionHandler : ConnectionHandler
    {
        public override async Task OnConnectedAsync(ConnectionContext connection)
        {
            IDuplexPipe pipe = connection.Transport;
            PipeReader pipeReader = pipe.Input;

            while (true)
            {
                ReadResult readResult = await pipeReader.ReadAsync();
                ReadOnlySequence<byte> readResultBuffer = readResult.Buffer;

               

                var s = GetString(readResultBuffer,Encoding.UTF8);
                Console.WriteLine(s);

                if (readResult.IsCompleted)
                {
                    break;
                }

                pipeReader.AdvanceTo(readResultBuffer.Start, readResultBuffer.End);
            }
        }

        public static string GetString( ReadOnlySequence<byte> payload,
            Encoding encoding = null)
        {
            encoding ??= Encoding.UTF8;
            return payload.IsSingleSegment ? encoding.GetString(payload.FirstSpan)
                : GetStringSlow(payload, encoding);

            static string GetStringSlow(in ReadOnlySequence<byte> payload, Encoding encoding)
            {
                // linearize
                int length = checked((int)payload.Length);
                var oversized = ArrayPool<byte>.Shared.Rent(length);
                try
                {
                    payload.CopyTo(oversized);
                    return encoding.GetString(oversized, 0, length);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(oversized);
                }
            }
        }
    }
}