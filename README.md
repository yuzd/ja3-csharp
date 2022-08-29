# ssl指纹
ssltest for aspnetcore


# 实现原理介绍
https://mp.weixin.qq.com/s/BvotXrFXwYvGWpqHKoj3uQ

# 如何提取tls指纹

```csharp
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
                            // tls指纹的提取 提取后会放在 Request.HttpContext.Connection.Id 
                             await TlsFilterConnectionMiddlewareExtensions.ProcessAsync(connectionContext, next, logger);
                           });

                           listenOption.UseHttps(httpsOptions);

                       });
                    });
                    webBuilder.UseStartup<Startup>();
                });
                
                

```

# 如何使用tls指纹
```csharp
[HttpGet]
        public string Get()
        {
            
            string sig =  Request.HttpContext.Connection.Id;
            if (string.IsNullOrEmpty(sig))
            {
                return "get sig fail";
            }

            var arr = sig.Split('@');
            if (arr.Length != 4)
            {
                return "get sig fail";
            }

            string tcpConnectionId = arr[0];
            string tlsHashOrigin = arr[1];
            string tlsHashMd5 = arr[2];
            string originText = arr[3];
            var arrOrigin = originText.Split('|');
            if (arrOrigin.Length != 5)
            {
                return "get sig origin fail";
            }
            string[] cipherList = arrOrigin[0].Split('-');
            string[] extentionList = arrOrigin[1].Split('-');
            string[] dhGroup = arrOrigin[2].Split('-');
            string[] _ecPointFormats = arrOrigin[3].Split('-');
            string tlsVersion = arrOrigin[4];

            return Newtonsoft.Json.JsonConvert.SerializeObject(new
            {
                tlsVersion = tlsVersion,
                tcpConnectionId = tcpConnectionId,
                tlsHashOrigin = tlsHashOrigin,
                tlsHashMd5 = tlsHashMd5,
                cipherList = cipherList,
                extentions = extentionList,
                supportedgroups = dhGroup,
                ecPointFormats = _ecPointFormats,
            }, Formatting.Indented);

        }
```
