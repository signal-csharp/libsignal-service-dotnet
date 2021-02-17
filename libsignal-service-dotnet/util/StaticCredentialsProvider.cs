namespace libsignalservice.util
{
    public class StaticCredentialsProvider : ICredentialsProvider
    {
        public string User { get; }
        public string Password { get; }
        public int DeviceId { get; }

        public StaticCredentialsProvider(string user, string password, int deviceId)
        {
            User = user;
            Password = password;
            DeviceId = deviceId;
        }
    }
}
