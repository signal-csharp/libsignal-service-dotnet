using System.IO;
using System.Threading;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a received SignalServiceAttachment "handle."  This
    /// is a pointer to the actual attachment content, which needs to be
    /// retrieved using <see cref="SignalServiceMessageReceiver.RetrieveAttachment(CancellationToken, SignalServiceAttachmentPointer, Stream, int, IProgressListener)"/>
    /// </summary>
    public class SignalServiceAttachmentPointer : SignalServiceAttachment
    {
        public ulong Id { get; }
        public byte[] Key { get; }
        public uint? Size { get; }
        public byte[]? Preview { get; }
        public byte[]? Digest { get; }
        public string? FileName { get; }
        public bool VoiceNote { get; }
        public int Width { get; }
        public int Height { get; }
        public string? Caption { get; }

        public SignalServiceAttachmentPointer(ulong id, string contentType, byte[] key,
            uint? size, byte[]? preview,
            int width, int height,
            byte[]? digest, string? fileName,
            bool voiceNote, string? caption)
            : base(contentType)
        {
            Id = id;
            Key = key;
            Size = size;
            Preview = preview;
            Digest = digest;
            FileName = fileName;
            VoiceNote = voiceNote;
            Width = width;
            Height = height;
            Caption = caption;
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
}
