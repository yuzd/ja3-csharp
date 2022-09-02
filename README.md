# NUGET
Install-Package Ja3Fingerprint

# OnLine Test
https://kawayiyi.com/tls

# tls指纹实现原理介绍
https://mp.weixin.qq.com/s/BvotXrFXwYvGWpqHKoj3uQ

# http2指纹实现原理介绍
 待写文章
 
# 如何使用

![image](https://dimg04.c-ctrip.com/images/0v50f120009x0k3rw360F.png)

# 如何获取tls&http2指纹
```csharp
        [HttpGet]
        public string Get()
        {
            // 指纹数据在这里面
            string sig =  Request.HttpContext.Connection.Id;

        }
```
