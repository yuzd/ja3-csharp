using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace ssltest
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
                        options.ListenLocalhost(5002, listenOption =>
                       {
                           var httpsOptions = new HttpsConnectionAdapterOptions();
                           //httpsOptions.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                           //httpsOptions.CheckCertificateRevocation = true;
                           //httpsOptions.ClientCertificateValidation +=
                           //    (certificate2, chain, arg3) =>
                           //    {
                           //        //return true;
                           //        //this is where we verify the thumbprint of a connected client matches the thumbprint we expect
                           //        //NOTE: this is just a simple example of verifying a client cert.
                           //        return certificate2.Thumbprint.Equals(
                           //           "2A39D43A8FE2CAE54542C768F61AE79097FAB6F5",
                           //           StringComparison.InvariantCultureIgnoreCase);
                           //    };
                           var serverCert = new X509Certificate2("server.pfx", "1234");
                           httpsOptions.ServerCertificate = serverCert;
                           listenOption.UseHttps(httpsOptions);
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
