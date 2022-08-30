//-----------------------------------------------------------------------
// <copyright file="myConnectionHeartbeatFeature .cs" company="Company">
// Copyright (C) Company. All Rights Reserved.
// </copyright>
// <author>nainaigu</author>
// <create>$Date$</create>
// <summary></summary>
//-----------------------------------------------------------------------

using Microsoft.AspNetCore.Connections.Features;

namespace ja3Csharp
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// 
    /// </summary>
    public class MyConnectionHeartbeatFeature :IConnectionHeartbeatFeature
    {
       
        
        public void OnHeartbeat(Action<object> action, object state)
        {
           Console.WriteLine("OnHeartbeat");
        }
    }
}