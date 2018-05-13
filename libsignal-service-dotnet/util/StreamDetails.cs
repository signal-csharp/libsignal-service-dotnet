using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.util
{
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
}
