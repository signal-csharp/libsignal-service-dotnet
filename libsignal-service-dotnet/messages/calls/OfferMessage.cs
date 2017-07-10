using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignal_service_dotnet.messages.calls
{
    public class OfferMessage
    {
        public ulong Id { get; set; }
        public string Description { get; set; }
    }
}
