using System.IO;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class DeviceGroupsInputStream : ChunkedInputStream
    {
        public DeviceGroupsInputStream(Stream input)
        : base(input)
        {
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
