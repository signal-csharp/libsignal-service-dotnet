namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public interface CredentialsProvider
    {
        string User { get; }

        string Password { get; }

        string SignalingKey { get; }

        int DeviceId { get; }
    }
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
}
