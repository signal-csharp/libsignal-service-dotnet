/** 
 * Copyright (C) 2017 smndtrl, golf1052
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
using System.IO;

namespace libsignalservice.messages
{
    public abstract class SignalServiceAttachment
    {
        private readonly String contentType;

        internal SignalServiceAttachment(String contentType)
        {
            this.contentType = contentType;
        }

        public String getContentType()
        {
            return contentType;
        }

        public abstract bool isStream();
        public abstract bool isPointer();

        public SignalServiceAttachmentStream asStream()
        {
            return (SignalServiceAttachmentStream)this;
        }

        public SignalServiceAttachmentPointer asPointer()
        {
            return (SignalServiceAttachmentPointer)this;
        }

        public static Builder newStreamBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private Stream inputStream;
            private string contentType;
            private long length;
            private ProgressListener listener;

            internal Builder()
            {
            }

            public Builder withStream(Stream inputStream)
            {
                this.inputStream = inputStream;
                return this;
            }

            public Builder withContentType(string contentType)
            {
                this.contentType = contentType;
                return this;
            }

            public Builder withLength(long length)
            {
                this.length = length;
                return this;
            }

            public Builder withListener(ProgressListener listener)
            {
                this.listener = listener;
                return this;
            }

            public SignalServiceAttachmentStream build()
            {
                if (inputStream == null)
                {
                    throw new ArgumentException("Must specify stream!");
                }
                if (contentType == null)
                {
                    throw new ArgumentException("No content type specified!");
                }
                if (length == 0)
                {
                    throw new ArgumentException("No length specified!");
                }

                return new SignalServiceAttachmentStream(inputStream, contentType, (uint)length, listener);
            }
        }

        public interface ProgressListener
        {
            /// <summary>
            /// Called on a progress change event.
            /// </summary>
            /// <param name="total">The total amount of transmit/receive in bytes.</param>
            /// <param name="progress">The amount that has been transmitted/received in bytes thus far</param>
            void onAttachmentProgress(long total, long progress);
        }
    }
}
