using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;

namespace Ja3Fingerprint
{
    public static class Ja3Extentions
    {

        public static IConnectionBuilder UseJa3Fingerprint(
            this ListenOptions connectionBuilder,Action<ListenOptions> call)
        {

             connectionBuilder.Use(async (connectionContext, next) =>
            {
                await TlsFilterConnectionMiddlewareExtensions.ProcessAsync(connectionContext, next);
            });

             call(connectionBuilder);

             return (connectionBuilder).Use((next => (context =>
             {
                 async Task Func()
                 {
                     await H2Extention.ProcessH2Async(context);
                     await next(context);
                 }

                 return Func();
             })));
        }
    }
}
