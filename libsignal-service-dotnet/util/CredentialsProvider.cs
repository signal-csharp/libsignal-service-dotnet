namespace libsignalservice.util
{
    public interface ICredentialsProvider
    {
        string User { get; }
        string Password { get; }
        int DeviceId { get; }
    }
}
