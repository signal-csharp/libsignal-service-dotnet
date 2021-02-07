using libsignalservice.push.exceptions;

namespace libsignalservice.push
{
    internal class DeviceLimitExceededException : NonSuccessfulResponseCodeException
    {
        public DeviceLimit Limit { get; set; }

        public DeviceLimitExceededException(DeviceLimit deviceLimit) : base(411)
        {
            Limit = deviceLimit;
        }
    }
}
