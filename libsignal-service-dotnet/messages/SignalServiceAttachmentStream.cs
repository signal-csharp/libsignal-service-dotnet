using System.IO;
using libsignalservice.util;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a local SignalServiceAttachment to be sent.
    /// </summary>
    public class SignalServiceAttachmentStream : SignalServiceAttachment
    {
        public Stream InputStream { get; }
        public long Length { get; }
        public string? FileName { get; }
        public IProgressListener? Listener { get; }
        public byte[]? Preview { get; }
        public bool VoiceNote { get; }
        public int Width { get; }
        public int Height { get; }
        public long UploadTimestamp { get; }
        public string? Caption { get; }
        public string? BlurHash { get; }

        public SignalServiceAttachmentStream(Stream inputStream, string contentType, long length, string? fileName, bool voiceNote, IProgressListener? listener)
           : this(inputStream, contentType, length, fileName, voiceNote, null, 0, 0, Util.CurrentTimeMillis(), null, null, listener)
        {
        }

        public SignalServiceAttachmentStream(Stream inputStream, string contentType, long length, string? fileName, bool voiceNote, byte[]? preview, int width, int height, long uploadTimestamp, string? caption, string? blurHash, IProgressListener? listener)
            : base(contentType)
        {
            InputStream = inputStream;
            Length = length;
            FileName = fileName;
            Listener = listener;
            VoiceNote = voiceNote;
            Preview = preview;
            Width = width;
            Height = height;
            UploadTimestamp = uploadTimestamp;
            Caption = caption;
            BlurHash = blurHash;
        }

        public override bool IsStream()
        {
            return true;
        }

        public override bool IsPointer()
        {
            return false;
        }
    }
}
