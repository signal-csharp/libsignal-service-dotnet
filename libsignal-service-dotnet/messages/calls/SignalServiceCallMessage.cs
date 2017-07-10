using System.Collections.Generic;

namespace libsignal_service_dotnet.messages.calls
{
    public class SignalServiceCallMessage
    {
        public OfferMessage OfferMessage;
        public AnswerMessage AnswerMessage;
        public HangupMessage HangupMessage;
        public BusyMessage BusyMessage;
        public List<IceUpdateMessage> IceUpdateMessages;
    }
}
