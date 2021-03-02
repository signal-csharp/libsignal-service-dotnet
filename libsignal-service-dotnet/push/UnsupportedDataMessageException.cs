using System;
using libsignalservice.messages;

namespace libsignalservice.push
{
    public class UnsupportedDataMessageException : Exception
    {
        public int RequiredVersion { get; }
        public string? Sender { get; }
        public int SenderDevice { get; }
        public SignalServiceGroup? Group { get; }

        public UnsupportedDataMessageException(int currentVersion,
            int requiredVersion,
            string? sender,
            int senderDevice,
            SignalServiceGroup? group) :
            base($"Required version: {requiredVersion}, Our version: {currentVersion}")
        {
            RequiredVersion = requiredVersion;
            Sender = sender;
            SenderDevice = senderDevice;
            Group = group;
        }
    }
}
