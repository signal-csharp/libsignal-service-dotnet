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
using Strilanc.Value;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a received SignalServiceAttachment "handle."  This
    /// is a pointer to the actual attachment content, which needs to be
    /// retrieved using <see cref="SignalServiceMessageReceiver.retrieveAttachment(SignalServiceAttachmentPointer, Windows.Storage.StorageFile)"/>
    /// </summary>
    public class SignalServiceAttachmentPointer : SignalServiceAttachment
    {

        private readonly ulong id;
        private readonly byte[] key;
        private readonly May<String> relay;
        private readonly May<uint> size;
        private readonly May<byte[]> preview;

        public SignalServiceAttachmentPointer(ulong id, String contentType, byte[] key, String relay, May<uint> size, May<byte[]> preview)
            : base(contentType)
        {
            this.id = id;
            this.key = key;
            this.relay = new May<String>(relay);
            this.size = size;
            this.preview = preview;
        }

        public SignalServiceAttachmentPointer(ulong id, String contentType, byte[] key, String relay)
        : this(id, contentType, key, relay, May<uint>.NoValue, May<byte[]>.NoValue)
        { }


        public ulong getId()
        {
            return id;
        }

        public byte[] getKey()
        {
            return key;
        }

        public override bool isStream()
        {
            return false;
        }


        public override bool isPointer()
        {
            return true;
        }

        public May<String> getRelay()
        {
            return relay;
        }
    }
}
