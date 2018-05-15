using System;
using System.Collections.Generic;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// Group information to include in SignalServiceMessages destined to groups.
    ///
    /// This class represents a "context" that is included with Signal Service messages
    /// to make them group messages.  There are three types of context:
    ///
    /// 1) Update -- Sent when either creating a group, or updating the properties
    /// of a group (such as the avatar icon, membership list, or title).
    /// 2) Deliver -- Sent when a message is to be delivered to an existing group.
    /// 3) Quit -- Sent when the sender wishes to leave an existing group.
    /// </summary>
    public class SignalServiceGroup
    {
        public enum GroupType
        {
            UNKNOWN,
            UPDATE,
            DELIVER,
            QUIT,
            REQUEST_INFO
        }

        public byte[] GroupId { get; set; }
        public GroupType Type { get; set; }
        public String Name { get; set; }
        public IList<String> Members { get; set; }
        public SignalServiceAttachment Avatar { get; set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
