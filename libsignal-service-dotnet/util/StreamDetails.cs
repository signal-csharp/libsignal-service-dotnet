using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.util
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class StreamDetails
    {
        public Stream InputStream { get; }
        public string ContentType { get; }
        public long Length { get; }

        public StreamDetails(Stream inputStream, string contentType, long length)
        {
            InputStream = inputStream;
            ContentType = contentType;
            Length = length;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
