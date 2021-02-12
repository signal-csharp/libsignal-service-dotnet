namespace libsignalservice.push.exceptions
{
    public class StaleDevicesException : NonSuccessfulResponseCodeException
    {
        public StaleDevices StaleDevices;

        public StaleDevicesException(StaleDevices staleDevices) : base(410)
        {
            StaleDevices = staleDevices;
        }
    }
}
