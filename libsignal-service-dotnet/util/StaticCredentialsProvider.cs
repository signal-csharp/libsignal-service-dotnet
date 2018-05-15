namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class StaticCredentialsProvider : CredentialsProvider
    {
        public string User { get; }
        public string Password { get; }
        public string SignalingKey { get; }
        public int DeviceId { get; }

        public StaticCredentialsProvider(string user, string password, string signalingKey, int deviceId)
        {
            User = user;
            Password = password;
            SignalingKey = signalingKey;
            DeviceId = deviceId;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
