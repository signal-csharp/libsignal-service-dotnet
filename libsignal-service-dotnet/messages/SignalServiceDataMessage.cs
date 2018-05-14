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
            public List<SignalServiceQuotedAttachment> Attachments { get; }

            public SignalServiceQuote(long id, SignalServiceAddress author, string text, List<SignalServiceQuotedAttachment> attachments)
            {
                Id = id;
                Author = author;
                Text = text;
                Attachments = attachments;
            }
        }

        public class SignalServiceQuotedAttachment
        {
            public string ContentType { get; }
            public string FileName { get; }
            public SignalServiceAttachment Thumbnail { get; }

            public SignalServiceQuotedAttachment(string contentType, string filename, SignalServiceAttachment thumbnail)
            {
                ContentType = contentType;
                FileName = filename;
                Thumbnail = thumbnail;
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
