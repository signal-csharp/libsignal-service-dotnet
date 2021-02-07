namespace libsignalservice.push.exceptions
{
    internal class MismatchedDevicesException : NonSuccessfulResponseCodeException
    {
        public MismatchedDevices MismatchedDevices { get; set; }

        public MismatchedDevicesException(MismatchedDevices mismatchedDevices) : base(409)
        {
            MismatchedDevices = mismatchedDevices;
        }
    }
}
