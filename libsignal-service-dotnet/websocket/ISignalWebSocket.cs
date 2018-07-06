using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace libsignalservice.websocket
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalWebSocketMessageReceivedEventArgs
    {
        public byte[] Message { get; set; }
    }

    public class SignalWebSocketClosedEventArgs
    {
        public ushort Code { get; set; }
        public string Reason { get; set; }
    }

    public interface ISignalWebSocket : IDisposable
    {
        void Close(UInt16 code, String reason);
        Task ConnectAsync();
        Task SendMessage(byte[] data);

        event EventHandler<SignalWebSocketClosedEventArgs> Closed;
        event EventHandler<SignalWebSocketMessageReceivedEventArgs> MessageReceived;
    }

    public interface ISignalWebSocketFactory
    {
        ISignalWebSocket CreateSignalWebSocket(CancellationToken token, Uri uri);
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
