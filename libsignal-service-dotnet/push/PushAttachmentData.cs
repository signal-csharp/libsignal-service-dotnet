using libsignaldotnet.push.http;
using System;
using System.IO;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class PushAttachmentData
    {
        public string ContentType { get; }
        public Stream Data { get; }
        public long DataSize { get; }
        public OutputStreamFactory OutputFactory { get; }
        public IProgressListener Listener { get; }

        public PushAttachmentData(String contentType, Stream data, long dataSize, OutputStreamFactory outputStreamFactory, IProgressListener listener)
        {
            ContentType = contentType;
            Data = data;
            DataSize = dataSize;
            OutputFactory = outputStreamFactory;
            Listener = listener;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
