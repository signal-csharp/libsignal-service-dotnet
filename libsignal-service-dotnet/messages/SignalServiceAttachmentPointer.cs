using System.IO;
using System.Threading;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a received SignalServiceAttachment "handle."  This
    /// is a pointer to the actual attachment content, which needs to be
    /// retrieved using <see cref="SignalServiceMessageReceiver.RetrieveAttachmentAsync(SignalServiceAttachmentPointer, Stream, int, CancellationToken?)"/>
    /// </summary>
    public class SignalServiceAttachmentPointer : SignalServiceAttachment
    {
        public int CdnNumber { get; }
        public SignalServiceAttachmentRemoteId RemoteId { get; }
        public byte[] Key { get; }
        public uint? Size { get; }
        public byte[]? Preview { get; }
        public byte[]? Digest { get; }
        public string? FileName { get; }
        public bool VoiceNote { get; }
        public int Width { get; }
        public int Height { get; }
        public string? Caption { get; }
        public string? BlurHash { get; }
        public long UploadTimestamp { get; }

        public SignalServiceAttachmentPointer(int cdnNumber, SignalServiceAttachmentRemoteId remoteId,
            string contentType, byte[] key,
            uint? size, byte[]? preview,
            int width, int height,
            byte[]? digest, string? fileName,
            bool voiceNote, string? caption,
            string? blurHash, long uploadTimestamp)
            : base(contentType)
        {
            CdnNumber = cdnNumber;
            RemoteId = remoteId;
            Key = key;
            Size = size;
            Preview = preview;
            Digest = digest;
            FileName = fileName;
            VoiceNote = voiceNote;
            Width = width;
            Height = height;
            Caption = caption;
            BlurHash = blurHash;
            UploadTimestamp = uploadTimestamp;
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
