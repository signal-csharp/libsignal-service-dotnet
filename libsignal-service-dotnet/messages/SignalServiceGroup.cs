using System.Collections.Generic;
using libsignalservice.push;

namespace libsignalservice.messages
{
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
        public string? Name { get; set; }
        public List<SignalServiceAddress>? Members { get; set; }
        public SignalServiceAttachment? Avatar { get; set; }

        /// <summary>
        /// Construct a DELIVER group context.
        /// </summary>
        /// <param name="groupId"></param>
        public SignalServiceGroup(byte[] groupId) :
            this(GroupType.DELIVER, groupId, null, null, null)
        {
        }

        /// <summary>
        /// Construct a group context.
        /// </summary>
        /// <param name="type">The group message type (update, deliver, quit).</param>
        /// <param name="groupId">The group ID.</param>
        /// <param name="name">The group title.</param>
        /// <param name="members">The group membership list.</param>
        /// <param name="avatar">The group avatar icon.</param>
        public SignalServiceGroup(GroupType type, byte[] groupId, string? name,
            List<SignalServiceAddress>? members,
            SignalServiceAttachment? avatar)
        {
            Type = type;
            GroupId = groupId;
            Name = name;
            Members = members;
            Avatar = avatar;
        }
    }
}
