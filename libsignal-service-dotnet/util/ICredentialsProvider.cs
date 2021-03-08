using System;

namespace libsignalservice.util
{
    public interface ICredentialsProvider
    {
        Guid? Uuid { get; }
        string? E164 { get; }
        string? Password { get; }
        int DeviceId { get; }
    }
}
