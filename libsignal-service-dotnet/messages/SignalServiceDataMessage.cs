/** 
 * Copyright (C) 2015-2017 smndtrl, golf1052
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Collections.Generic;
using libsignal.util;
using libsignalservice.util;
using Strilanc.Value;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a decrypted Signal Service data message.
    /// </summary>
    public class SignalServiceDataMessage
    {
        private readonly long timestamp;
        private readonly May<List<SignalServiceAttachment>> attachments;
        private readonly May<string> body;
        private readonly May<SignalServiceGroup> group;
        private readonly bool endSession;
        private readonly bool expirationUpdate;
        private readonly int expiresInSeconds;

        /// <summary>
        /// Construct a SignalServiceDataMessage with a body and no attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, string body)
            : this(timestamp, body, 0)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage with a body and no attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds">The number of seconds in which a message should disappear after having been seen.</param>
        public SignalServiceDataMessage(long timestamp, string body, int expiresInSeconds)
        {
        }

        public SignalServiceDataMessage(long timestamp, SignalServiceAttachment attachment, string body)
            : this(timestamp, new List<SignalServiceAttachment>(new[] { attachment }), body)
        {
        }

        /// <summary>
        /// Construct a SignalServiceDataMessage with a body and list of attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, List<SignalServiceAttachment> attachments, string body)
            : this(timestamp, null, attachments, body)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage with a body and list of attachments.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds">The number of seconds in which a message should disappear after having been seen.</param>
        public SignalServiceDataMessage(long timestamp, List<SignalServiceAttachment> attachments, string body, int expiresInSeconds)
            : this(timestamp, null, attachments, body, expiresInSeconds)
        {
        }

        /// <summary>
        /// Construct a SignalServiceDataMessage group message with attachments and body.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="group">The group information.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        public SignalServiceDataMessage(long timestamp, SignalServiceGroup group, List<SignalServiceAttachment> attachments, string body)
            : this(timestamp, group, attachments, body, 0)
        {
        }

        /// <summary>
        /// Construct an expiring SignalServiceDataMessage group message with attachments and body.
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="group">The group information.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="expiresInSeconds">The number of seconds in which a message should disappear after having been seen.</param>
        public SignalServiceDataMessage(long timestamp, SignalServiceGroup group, List<SignalServiceAttachment> attachments, string body, int expiresInSeconds)
            : this(timestamp, group, attachments, body, false, expiresInSeconds, false)
        {
        }

        /// <summary>
        /// Construct a SignalServiceDataMessage
        /// </summary>
        /// <param name="timestamp">The sent timestamp.</param>
        /// <param name="group">The group information.</param>
        /// <param name="attachments">The attachments.</param>
        /// <param name="body">The message contents.</param>
        /// <param name="endSession">Flag indicating whether this message should close a session.</param>
        /// <param name="expiresInSeconds">The number of seconds in which a message should disappear after having been seen.</param>
        public SignalServiceDataMessage(long timestamp,
            SignalServiceGroup group,
            List<SignalServiceAttachment> attachments,
            string body,
            bool endSession,
            int expiresInSeconds,
            bool expirationUpdate)
        {
            this.timestamp = timestamp;
            this.body = new May<string>(body);
            this.group = group == null ? May<SignalServiceGroup>.NoValue : new May<SignalServiceGroup>(group);
            this.endSession = endSession;
            this.expiresInSeconds = expiresInSeconds;
            this.expirationUpdate = expirationUpdate;

            if (attachments != null && !(attachments.Count == 0))
            {
                this.attachments = new May<List<SignalServiceAttachment>>(attachments);
            }
            else
            {
                this.attachments = May<List<SignalServiceAttachment>>.NoValue;
            }
        }

        public static Builder newBuilder()
        {
            return new Builder();
        }

        /// <summary>
        /// The message timestamp.
        /// </summary>
        /// <returns>The message timestamp.</returns>
        public long getTimestamp()
        {
            return timestamp;
        }

        /// <summary>
        /// The message attachments (if any).
        /// </summary>
        /// <returns>The message attachments (if any).</returns>
        public May<List<SignalServiceAttachment>> getAttachments()
        {
            return attachments;
        }

        /// <summary>
        /// The message body (if any).
        /// </summary>
        /// <returns>The message body (if any).</returns>
        public May<string> getBody()
        {
            return body;
        }

        /// <summary>
        /// The message group info (if any).
        /// </summary>
        /// <returns>The message group info (if any).</returns>
        public May<SignalServiceGroup> getGroupInfo()
        {
            return group;
        }

        public bool isEndSession()
        {
            return endSession;
        }

        public bool isExpirationUpdate()
        {
            return expirationUpdate;
        }

        public bool isGroupUpdate()
        {
            return group.HasValue && group.ForceGetValue().getType() != SignalServiceGroup.Type.DELIVER;
        }

        public int getExpiresInSeconds()
        {
            return expiresInSeconds;
        }
    }

    public class Builder
    {
        private List<SignalServiceAttachment> attachments = new List<SignalServiceAttachment>();
        private long timestamp;
        private SignalServiceGroup group;
        private string body;
        private bool endSession;
        private int expiresInSeconds;
        private bool expirationUpdate;

        public Builder() { }

        public Builder withTimestamp(long timestamp)
        {
            this.timestamp = timestamp;
            return this;
        }

        public Builder asGroupMessage(SignalServiceGroup group)
        {
            this.group = group;
            return this;
        }

        public Builder withAttachment(SignalServiceAttachment attachment)
        {
            attachments.Add(attachment);
            return this;
        }

        public Builder withAttachments(List<SignalServiceAttachment> attachments)
        {
            foreach (SignalServiceAttachment attachment in attachments)
            {
                this.attachments.Add(attachment);
            }

            return this;
        }

        public Builder withBody(string body)
        {
            this.body = body;
            return this;
        }

        public Builder asEndSessionMessage()
        {
            return asEndSessionMessage(true);
        }

        public Builder asEndSessionMessage(bool endSession)
        {
            this.endSession = endSession;
            return this;
        }

        public Builder asExpirationUpdate()
        {
            return asExpirationUpdate(true);
        }

        private Builder asExpirationUpdate(bool expirationUpdate)
        {
            this.expirationUpdate = expirationUpdate;
            return this;
        }

        public Builder withExpiration(int expiresInSeconds)
        {
            this.expiresInSeconds = expiresInSeconds;
            return this;
        }

        public SignalServiceDataMessage build()
        {
            if (timestamp == 0) timestamp = Util.CurrentTimeMillis();
            return new SignalServiceDataMessage(timestamp, group, attachments, body, endSession, expiresInSeconds, expirationUpdate);
        }
    }
}
