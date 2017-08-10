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

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a received SignalServiceAttachment "handle."  This
    /// is a pointer to the actual attachment content, which needs to be
    /// retrieved using <see cref="SignalServiceMessageReceiver.retrieveAttachment(SignalServiceAttachmentPointer, Windows.Storage.StorageFile)"/>
    /// </summary>
    public class SignalServiceAttachmentPointer : SignalServiceAttachment
    {
        public ulong Id { get; }
        public byte[] Key { get; }
        public string Relay { get; }
        public uint? Size { get; }
        public byte[] Preview { get; }
        public byte[] Digest { get; }
        public string FileName { get; }
        public bool VoiceNote { get; }

        public SignalServiceAttachmentPointer(ulong id, string contentType, byte[] key, string relay, byte[] digest, string fileName, bool voiceNote)
        : this(id, contentType, key, relay, null, null, digest, fileName, voiceNote)
        { }

        public SignalServiceAttachmentPointer(ulong id, string contentType, byte[] key, string relay, uint? size, byte[] preview, byte[] digest, string fileName, bool voiceNote)
            : base(contentType)
        {
            Id = id;
            Key = key;
            Relay = relay;
            Size = size;
            Preview = preview;
            Digest = digest;
            FileName = fileName;
            VoiceNote = voiceNote;
        }

        public override bool isStream()
        {
            return false;
        }

        public override bool isPointer()
        {
            return true;
        }
    }
}
