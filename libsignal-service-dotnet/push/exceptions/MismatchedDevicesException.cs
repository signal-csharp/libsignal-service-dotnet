namespace libsignalservice.push.exceptions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class MismatchedDevicesException : NonSuccessfulResponseCodeException
    {
        public MismatchedDevices MismatchedDevices { get; set; }

        public MismatchedDevicesException(MismatchedDevices mismatchedDevices)
        {
            this.MismatchedDevices = mismatchedDevices;
        }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
