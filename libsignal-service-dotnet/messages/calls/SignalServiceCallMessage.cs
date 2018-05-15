using System.Collections.Generic;

namespace libsignal_service_dotnet.messages.calls
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceCallMessage
    {
        public OfferMessage OfferMessage;
        public AnswerMessage AnswerMessage;
        public HangupMessage HangupMessage;
        public BusyMessage BusyMessage;
        public List<IceUpdateMessage> IceUpdateMessages;
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
