using libsignalservice.push.exceptions;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceLimitExceededException : NonSuccessfulResponseCodeException
    {
        public DeviceLimit Limit { get; set; }

        public DeviceLimitExceededException(DeviceLimit deviceLimit)
        {
            this.Limit = deviceLimit;
        }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
