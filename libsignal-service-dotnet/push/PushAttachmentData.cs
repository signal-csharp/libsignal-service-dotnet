using System;
using System.IO;
using libsignaldotnet.push.http;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    public class PushAttachmentData
    {
        public string ContentType { get; }
        public Stream Data { get; }
        public long DataSize { get; }
        public IOutputStreamFactory OutputFactory { get; }
        public IProgressListener? Listener { get; }

        public PushAttachmentData(string contentType, Stream data, long dataSize, IOutputStreamFactory outputStreamFactory, IProgressListener? listener)
        {
            ContentType = contentType;
            Data = data;
            DataSize = dataSize;
            OutputFactory = outputStreamFactory;
            Listener = listener;
        }
    }
}
