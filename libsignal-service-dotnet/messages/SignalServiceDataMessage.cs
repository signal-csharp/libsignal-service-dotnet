using System.Collections.Generic;
using libsignalservice.messages.shared;
using libsignalservice.push;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a decrypted Signal Service data message.
    /// </summary>
    public class SignalServiceDataMessage
    {
        public long Timestamp { get; set; }
        public List<SignalServiceAttachment>? Attachments { get; set; }
        public string? Body { get; set; }
        public SignalServiceGroup? Group { get; set; }
        public byte[]? ProfileKey { get; set; }
        public bool EndSession { get; set; }
        public bool ExpirationUpdate { get; set; }
        public int ExpiresInSeconds { get; set; }
        public bool ProfileKeyUpdate { get; set; }
        public SignalServiceQuote? Quote { get; set; }
        public List<SharedContact>? SharedContacts { get; set; }
        public List<SignalServicePreview>? Previews { get; set; }
        public SignalServiceSticker? Sticker { get; set; }
        public bool ViewOnce { get; set; }

        /// <summary>
        /// Construct a SignalServiceDataMessage with a body and no attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, string body) :
            this(timestamp, body, 0)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage with a body and no attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds">The number of seconds in which the message should expire after having been seen.</param>
        public SignalServiceDataMessage(long timestamp, string body, int expiresInSeconds) :
            this(timestamp, null, body, expiresInSeconds)
        {
        }

        public SignalServiceDataMessage(long timestamp, SignalServiceAttachment attachment, string body) :
            this(timestamp, new List<SignalServiceAttachment>() { attachment }, body)
        {
        }

        /// <summary>
        /// Construct a SignalServiceDataMessage with a body and list of attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, List<SignalServiceAttachment> attachments, string body) :
            this(timestamp, attachments, body, 0)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage with a body and list of attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds">The number of seconds in which the message should expire after having been seen.</param>
        public SignalServiceDataMessage(long timestamp, List<SignalServiceAttachment>? attachments, string body, int expiresInSeconds) :
            this(timestamp, null, attachments, body, expiresInSeconds)
        {
        }

        /// <summary>
        /// Construct a SignalServiceDataMessage group message with attachments and body.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="group">The group information.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, SignalServiceGroup? group, List<SignalServiceAttachment>? attachments, string body) :
            this(timestamp, group, attachments, body, 0)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage group message with attachments and body.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="group">The group information.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds"></param>
        public SignalServiceDataMessage(long timestamp, SignalServiceGroup? group, List<SignalServiceAttachment>? attachments, string body, int expiresInSeconds) :
            this(timestamp, group, attachments, body, false, expiresInSeconds, false, null, false, null, null, null, null, false)
        {
        }

        public SignalServiceDataMessage(long timestamp, SignalServiceGroup? group,
            List<SignalServiceAttachment>? attachments,
            string body, bool endSession, int expiresInSeconds,
            bool expirationUpdate, byte[]? profileKey, bool profileKeyUpdate,
            SignalServiceQuote? quote, List<SharedContact>? sharedContacts, List<SignalServicePreview>? previews,
            SignalServiceSticker? sticker, bool viewOnce)
        {
            Timestamp = timestamp;
            Body = body;
            Group = group;
            EndSession = endSession;
            ExpiresInSeconds = expiresInSeconds;
            ExpirationUpdate = expirationUpdate;
            ProfileKey = profileKey;
            ProfileKeyUpdate = profileKeyUpdate;
            Quote = quote;
            Sticker = sticker;
            ViewOnce = viewOnce;

            if (attachments != null && attachments.Count > 0)
            {
                Attachments = attachments;
            }
            else
            {
                Attachments = null;
            }

            if (sharedContacts != null && sharedContacts.Count > 0)
            {
                SharedContacts = sharedContacts;
            }
            else
            {
                SharedContacts = null;
            }

            if (previews != null && previews.Count > 0)
            {
                Previews = previews;
            }
            else
            {
                Previews = null;
            }
        }

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
            public SignalServiceAttachment? Thumbnail { get; }

            public SignalServiceQuotedAttachment(string contentType, string filename, SignalServiceAttachment? thumbnail)
            {
                ContentType = contentType;
                FileName = filename;
                Thumbnail = thumbnail;
            }
        }

        public class SignalServicePreview
        {
            public string Url { get; }
            public string Title { get; }
            public SignalServiceAttachment? Image { get; }

            public SignalServicePreview(string url, string title, SignalServiceAttachment? image)
            {
                Url = url;
                Title = title;
                Image = image;
            }
        }

        public class SignalServiceSticker
        {
            public byte[] PackId { get; }
            public byte[] PackKey { get; }
            public int StickerId { get; }
            public SignalServiceAttachment Attachment { get; }

            public SignalServiceSticker(byte[] packId, byte[] packKey, int stickerId, SignalServiceAttachment attachment)
            {
                PackId = packId;
                PackKey = packKey;
                StickerId = stickerId;
                Attachment = attachment;
            }
        }
    }
}
