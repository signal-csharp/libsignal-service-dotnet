using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class LibsignalLogging
    {
        public static ILoggerFactory LoggerFactory { get; } = new LoggerFactory();
        public static ILogger CreateLogger<T>() => LoggerFactory.CreateLogger<T>();
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
