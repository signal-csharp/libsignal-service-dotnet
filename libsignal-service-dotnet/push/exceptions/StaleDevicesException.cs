using System;

namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class StaleDevicesException : Exception
    {
        public StaleDevices StaleDevices;

        public StaleDevicesException(StaleDevices staleDevices)
        {
            StaleDevices = staleDevices;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
