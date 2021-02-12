namespace libsignalservice.push.exceptions
{
    public class MismatchedDevicesException : NonSuccessfulResponseCodeException
    {
        public MismatchedDevices MismatchedDevices { get; set; }

        public MismatchedDevicesException(MismatchedDevices mismatchedDevices) : base(409)
        {
            MismatchedDevices = mismatchedDevices;
        }
    }
}
