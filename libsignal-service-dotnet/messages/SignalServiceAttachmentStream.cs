using Strilanc.Value;

using System;
using System.IO;

namespace libsignalservice.messages
{
    /// <summary>
    /// Represents a local SignalServiceAttachment to be sent.
    /// </summary>
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceAttachmentStream : SignalServiceAttachment
    {
        public Stream InputStream { get; }
        public long Length { get; }
        public string FileName { get; }
        public IProgressListener Listener { get; }
        public byte[] Preview { get; }
        public bool VoiceNote { get; }
        public int Width { get; }
        public int Height { get; }
        

        public SignalServiceAttachmentStream(Stream inputStream, string contentType, long length, string fileName, bool voiceNote, IProgressListener listener)
           : this(inputStream, contentType, length, fileName, voiceNote, null, 0, 0, listener)
        {
        }

        public SignalServiceAttachmentStream(Stream inputStream, String contentType, long length, string fileName, bool voiceNote, byte[] preview, int width, int height, IProgressListener listener)
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
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
