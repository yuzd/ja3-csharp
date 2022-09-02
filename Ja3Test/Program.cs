using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Ja3Fingerprint;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;

namespace Ja3Test
{
    public class Program
    {

        public static void Main(string[] args)
        {
            var config = File.ReadAllText("appsettings.json");
            if (string.IsNullOrEmpty(config))
            {
                throw new Exception("application.json not found");
            }

            var data = JsonConvert.DeserializeObject<Config>(config);
            CreateHostBuilder(data,args).Build().Run();
        }

         static IHostBuilder CreateHostBuilder(Config data,string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseKestrel(options =>
                    {
                        var logger = options.ApplicationServices.GetRequiredService<ILogger<Program>>();

                        options.ListenAnyIP(data.Port, listenOption =>
                        {
                            var httpsOptions = new HttpsConnectionAdapterOptions();

                            var serverCert = new X509Certificate2(data.Pfx, data.Pwd);
                            httpsOptions.ServerCertificate = serverCert;

                            listenOption.UseJa3Fingerprint((_) =>
                            {
                                listenOption.UseHttps(httpsOptions);
                            });

                           
                      });
                    });
                    webBuilder.UseStartup<Startup>();
                });

    }

    class Config
    {
        public string Pfx { get; set; }
        public string Pwd { get; set; }
        public int Port { get; set; }
    }
}