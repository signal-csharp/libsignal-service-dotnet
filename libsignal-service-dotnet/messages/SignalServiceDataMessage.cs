using libsignalservice.push;
using System.Collections.Generic;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    /// <summary>
    /// Represents a decrypted Signal Service data message.
    /// </summary>
    public class SignalServiceDataMessage
    {
        public long Timestamp { get; set; }
        public List<SignalServiceAttachment> Attachments { get; set; }
        public string Body { get; set; }
        public SignalServiceGroup Group { get; set; }
        public byte[] ProfileKey { get; set; }
        public bool EndSession { get; set; }
        public bool ExpirationUpdate { get; set; }
        public int ExpiresInSeconds { get; set; }
        public bool ProfileKeyUpdate { get; set; }
        public SignalServiceQuote Quote { get; set; }

        public bool IsProfileKeyUpdate()
        {
            return ProfileKeyUpdate;
        }

        public bool IsGroupUpdate()
        {
            return Group != null && Group.Type != SignalServiceGroup.GroupType.DELIVER;
        }

        public class SignalServiceQuote
        {
            public long Id { get; }
            public SignalServiceAddress Author { get; }
            public string Text { get; }
            public List<SignalServiceAttachment> Attachments { get; }

            public SignalServiceQuote(long id, SignalServiceAddress author, string text, List<SignalServiceAttachment> attachments)
            {
                Id = id;
                Author = author;
                Text = text;
                Attachments = attachments;
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
