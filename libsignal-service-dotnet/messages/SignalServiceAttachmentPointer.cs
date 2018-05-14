using System.IO;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a received SignalServiceAttachment "handle."  This
    /// is a pointer to the actual attachment content, which needs to be
    /// retrieved using <see cref="SignalServiceMessageReceiver.RetrieveAttachment(SignalServiceAttachmentPointer, Stream, int, IProgressListener)"/>
    /// </summary>
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
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
        public int Width { get; }
        public int Height { get; }

        public SignalServiceAttachmentPointer(ulong id, string contentType, byte[] key, string relay, uint? size, byte[] preview, int width, int height, byte[] digest, string fileName, bool voiceNote)
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
            Width = width;
            Height = height;
        }

        public override bool IsStream()
        {
            return false;
        }

        public override bool IsPointer()
        {
            return true;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
