using System;

namespace libsignalservice.util
{
    public class StaticCredentialsProvider : ICredentialsProvider
    {
        public Guid? Uuid { get; }
        public string? E164 { get; }
        public string? Password { get; }
        public int DeviceId { get; }

        public StaticCredentialsProvider(Guid? uuid, string? e164, string? password, int deviceId)
        {
            Uuid = uuid;
            E164 = e164;
            Password = password;
            DeviceId = deviceId;
        }
    }
}
