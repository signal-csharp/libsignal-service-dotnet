using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using libsignaldotnet.push.http;
using libsignalservice.crypto;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push.http
{
    internal class DigestingRequestBody : HttpContent
    {
        private readonly Stream inputStream;
        private readonly IOutputStreamFactory outputStreamFactory;
        private readonly string contentType;
        private readonly long contentLength;
        private readonly IProgressListener? progressListener;
        private readonly CancellationToken cancellationToken;

        private byte[]? digest;

        public DigestingRequestBody(Stream inputStream,
            IOutputStreamFactory outputStreamFactory,
            string contentType, long contentLength,
            IProgressListener? progressListener,
            CancellationToken? cancellationToken)
        {
            this.inputStream = inputStream;
            this.outputStreamFactory = outputStreamFactory;
            this.contentType = contentType;
            this.contentLength = contentLength;
            this.progressListener = progressListener;
            if (!cancellationToken.HasValue)
            {
                this.cancellationToken = CancellationToken.None;
            }
            else
            {
                this.cancellationToken = cancellationToken.Value;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="stream"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        /// <exception cref="OperationCanceledException"></exception>
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext context)
        {
            DigestingOutputStream outputStream = outputStreamFactory.CreateFor(stream);
            byte[] buffer = new byte[8192];

            int read;
            long total = 0;

            while ((read = inputStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    throw new OperationCanceledException("Canceled!", cancellationToken);
                }
                outputStream.Write(buffer, 0, read);
                total += read;

                if (progressListener != null)
                {
                    progressListener.OnAttachmentProgress(contentLength, total);
                }
            }

            outputStream.Flush();
            digest = outputStream.GetTransmittedDigest();

            return Task.CompletedTask;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = contentLength;
            return true;
        }

        public byte[] GetTransmittedDigest()
        {
            return digest!;
        }
    }
}
