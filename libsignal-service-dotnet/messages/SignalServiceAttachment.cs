using System;
using System.IO;

namespace libsignalservice.messages
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public abstract class SignalServiceAttachment
    {
        public String ContentType { get; }

        internal SignalServiceAttachment(String contentType)
        {
            this.ContentType = contentType;
        }

        public abstract bool IsStream();

        public abstract bool IsPointer();

        public SignalServiceAttachmentStream AsStream()
        {
            return (SignalServiceAttachmentStream)this;
        }

        public SignalServiceAttachmentPointer AsPointer()
        {
            return (SignalServiceAttachmentPointer)this;
        }

        public class Builder
        {
            private Stream InputStream;
            private string ContentType;
            private string FileName;
            private long Length;
            private IProgressListener Listener;
            private bool VoiceNote;
            private int Width;
            private int Height;

            Builder()
            {
            }

            public Builder WithStream(Stream inputStream)
            {
                InputStream = inputStream;
                return this;
            }

            public Builder WithContentType(string contentType)
            {
                ContentType = contentType;
                return this;
            }

            public Builder WithLength(long length)
            {
                Length = length;
                return this;
            }

            public Builder WithFileName(string fileName)
            {
                FileName = fileName;
                return this;
            }

            public Builder WithListener(IProgressListener listener)
            {
                Listener = listener;
                return this;
            }

            public Builder WithVoiceNote(bool voiceNote)
            {
                VoiceNote = voiceNote;
                return this;
            }

            public Builder WithWidth(int width)
            {
                Width = width;
                return this;
            }

            public Builder WithHeight(int height)
            {
                Height = height;
                return this;
            }

            public SignalServiceAttachmentStream Build()
            {
                if (InputStream == null)
                {
                    throw new ArgumentException("Must specify stream!");
                }
                if (ContentType == null)
                {
                    throw new ArgumentException("No content type specified!");
                }
                if (Length == 0)
                {
                    throw new ArgumentException("No length specified!");
                }

                return new SignalServiceAttachmentStream(InputStream, ContentType, (uint)Length, FileName, VoiceNote, null, Width, Height, Listener);
            }
        }

        public interface IProgressListener
        {
            /// <summary>
            /// Called on a progress change event.
            /// </summary>
            /// <param name="total">The total amount of transmit/receive in bytes.</param>
            /// <param name="progress">The amount that has been transmitted/received in bytes thus far</param>
            void OnAttachmentProgress(long total, long progress);
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
