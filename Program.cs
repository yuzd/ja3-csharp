using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

namespace ja3Csharp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseKestrel(options =>
                    {
                        var logger = options.ApplicationServices.GetRequiredService<ILogger<Program>>();


                        options.ListenAnyIP(5002, listenOption =>
                        {
                            var httpsOptions = new HttpsConnectionAdapterOptions();

                            var serverCert = new X509Certificate2("server.pfx", "1234");
                            httpsOptions.ServerCertificate = serverCert;

                            listenOption.Use(async (connectionContext, next) =>
                            {
                                await TlsFilterConnectionMiddlewareExtensions.ProcessAsync(connectionContext, next, logger);
                            });


                            //listenOption.UseConnectionHandler<MyTCPConnectionHandler>();
                            listenOption.UseHttps(httpsOptions);
                            //listenOption.UseTlsFilter();
                            // listenOption.Use((context, next) =>
                            // {
                            //     Func<Task> func = (Func<Task>) (() => next(context));
                            //    return  n.Invoke();
                            // });

                            listenOption.Use( (next => (context =>
                            {
                                async Task Func()
                                {
                                    await TlsFilterConnectionMiddlewareExtensions.ProcessH2Async(context, logger);
                                    await next(context);
                                }

                                return Func();
                            })));
                        });
                    });
                    webBuilder.UseStartup<Startup>();
                });


        private static async Task<string> GetApiDataAsync()
        {
            try
            {
                //var cert = new X509Certificate2("server.pfx", "1234");
                var handler = new HttpClientHandler();
                //handler.ClientCertificates.Add(cert);
                handler.Proxy = new WebProxy("127.0.0.1:8888");

                var client = new HttpClient(handler);

                handler.ServerCertificateCustomValidationCallback = (request, cert, chain, errors) =>
                {
                    //this verifies the server API cert against expected thumprint
                    return cert.Thumbprint.Equals("2A39D43A8FE2CAE54542C768F61AE79097FAB6F5",
                        StringComparison.CurrentCultureIgnoreCase);
                };

                var request = new HttpRequestMessage()
                {
                    RequestUri = new Uri("https://localhost:5002/WeatherForecast"),
                    Method = HttpMethod.Get,
                };

                var response = await client.SendAsync(request);

                if (response.IsSuccessStatusCode)
                {
                    var responseContent = await response.Content.ReadAsStringAsync();
                    return responseContent;
                }

                throw new ApplicationException($"Status code: {response.StatusCode}, Error: {response.ReasonPhrase}");
            }
            catch (Exception e)
            {
                throw new ApplicationException($"Exception {e}");
            }
        }
    }
}