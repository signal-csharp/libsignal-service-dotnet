using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignal_service_dotnet.messages.calls
{
    public class IceUpdateMessage
    {
        public ulong Id { get; set; }
        public string SdpMid { get; set; }
        public uint SdpMLineIndex { get; set; }
        public string Sdp { get; set; }
    }
}
