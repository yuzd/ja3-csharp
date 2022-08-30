using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.OpenApi.Models;
using System;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ja3Csharp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            //services.AddCertificateForwarding(options =>
            //{
            //    options.CertificateHeader = "X-ARR-ClientCert";
            //    options.HeaderConverter = (headerValue) =>
            //    {
            //        X509Certificate2 clientCertificate = null;
            //        if (!string.IsNullOrWhiteSpace(headerValue))
            //        {
            //            byte[] bytes = StringToByteArray(headerValue);
            //            clientCertificate = new X509Certificate2(bytes);
            //        }

            //        return clientCertificate;
            //    };
            //});


            //services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            //    .AddCertificate(options =>
            //    {
            //        options.AllowedCertificateTypes = CertificateTypes.SelfSigned;
            //        options.Events = new CertificateAuthenticationEvents
            //        {
            //            OnCertificateValidated = context =>
            //            {
            //                var validationService = new MyCertificateValidationService();
            //                if (validationService.ValidateCertificate(context.ClientCertificate))
            //                {
            //                    var claims = new[] {
            //                        new Claim(ClaimTypes.NameIdentifier, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer),
            //                        new Claim(ClaimTypes.Name, context.ClientCertificate.Subject, ClaimValueTypes.String, context.Options.ClaimsIssuer)
            //                    };
            //                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims, context.Scheme.Name));
            //                    context.Success();
            //                }
            //                else { context.Fail("invalid cert"); }
            //                return Task.CompletedTask;
            //            },
            //            OnAuthenticationFailed = context =>
            //            {
            //                context.Fail("invalid cert");
            //                return Task.CompletedTask;
            //            }
            //        };
            //    });


            services.TryAddSingleton<MyConnectionHeartbeatFeature>();
            services.AddControllers();
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "ssltest", Version = "v1" });
            });
            
            
        }

        private static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "ssltest v1"));
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            //app.UseCertificateForwarding();
            //app.UseAuthentication();

            //app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
