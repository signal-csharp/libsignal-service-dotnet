using System.Collections.Generic;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class BlockedListMessage
    {
        public List<string> Numbers { get; }
        public List<byte[]> GroupIds { get; }

        public BlockedListMessage(List<string> numbers, List<byte[]> groupIds)
        {
            Numbers = numbers;
            GroupIds = groupIds;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
