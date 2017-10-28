using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Text;

namespace libsignalservice
{
    public class LibsignalLogging
    {
        public static ILoggerFactory LoggerFactory { get; } = new LoggerFactory();
        public static ILogger CreateLogger<T>() => LoggerFactory.CreateLogger<T>();
    }
}
