using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http;
using System.Net.Security;
using Newtonsoft.Json;

namespace ja3Csharp.Controllers
{
    [ApiController]
    [Route("[controller]")]
    //[Authorize]
    public class TlsController : ControllerBase
    {
        

        [HttpGet]
        public string Get()
        {
            
            string sig =  Request.HttpContext.Connection.Id;
            if (string.IsNullOrEmpty(sig))
            {
                return "get sig fail";
            }

            var arr = sig.Split('@');
            if (arr.Length < 4)
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


            var h2D = new Dictionary<string,object>();
            string h2 = arr.Length > 4 ? arr[4] : "";
            if (!string.IsNullOrEmpty(h2))
            {
                var arr2 = h2.Split('^');
                if (arr2.Length == 3)
                {
                    var settings = arr2[1];
                    var updateWindows = arr2[2];
                    var settings_detail = settings.Split(new string[] { "->" }, StringSplitOptions.None);
                    var updateWindows_detail = updateWindows.Split(new string[] { "->" }, StringSplitOptions.None);
                    h2D.Add(settings_detail[0],JsonConvert.DeserializeObject<Dictionary<string,string>>(settings_detail[1])); 
                    h2D.Add(updateWindows_detail[0],updateWindows_detail[1]); 
                }
               
                
            }
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
                proto = HttpContext.Request.Protocol ,
                h2 = h2D
            }, Formatting.Indented);

        }
    }
}
