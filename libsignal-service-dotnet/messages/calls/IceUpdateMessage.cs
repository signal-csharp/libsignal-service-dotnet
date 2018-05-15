namespace libsignal_service_dotnet.messages.calls
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class IceUpdateMessage
    {
        public ulong Id { get; set; }
        public string SdpMid { get; set; }
        public uint SdpMLineIndex { get; set; }
        public string Sdp { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
