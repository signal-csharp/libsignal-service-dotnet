using static libsignalservice.push.SyncMessage.Types;

namespace libsignalservice.messages.multidevice
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class RequestMessage
    {
        public Request Request { get; }

        public RequestMessage(Request request)
        {
            this.Request = request;
        }

        public bool IsContactsRequest()
        {
            return Request.Type == Request.Types.Type.Contacts;
        }

        public bool IsGroupsRequest()
        {
            return Request.Type == Request.Types.Type.Groups;
        }

        public bool IsBlockedListRequest()
        {
            return Request.Type == Request.Types.Type.Blocked;
        }

        public bool IsConfigurationRequest()
        {
            return Request.Type == Request.Types.Type.Configuration;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
