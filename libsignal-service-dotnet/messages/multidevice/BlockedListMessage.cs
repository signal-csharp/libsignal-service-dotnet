using System.Collections.Generic;
using libsignalservice.push;

namespace libsignalservice.messages.multidevice
{
    public class BlockedListMessage
    {
        public List<SignalServiceAddress> Addresses { get; }
        public List<byte[]> GroupIds { get; }

        public BlockedListMessage(List<SignalServiceAddress> addresses, List<byte[]> groupIds)
        {
            Addresses = addresses;
            GroupIds = groupIds;
        }
    }
}
