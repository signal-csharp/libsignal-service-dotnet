using libsignaldotnet.push.http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace libsignalservice.push
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class ProfileAvatarData
    {
        public Stream InputData { get; }
        public long DataLength { get; }
        public string ContentType { get; }
        public OutputStreamFactory OutputStreamFactory { get; }

        public ProfileAvatarData(Stream inputData, long dataLength, string contentType, OutputStreamFactory outputStreamFactory)
        {
            InputData = inputData;
            DataLength = dataLength;
            ContentType = contentType;
            OutputStreamFactory = outputStreamFactory;
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
