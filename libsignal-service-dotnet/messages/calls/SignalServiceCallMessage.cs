using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
