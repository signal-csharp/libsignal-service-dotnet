using System;
using System.Threading;
using System.Threading.Tasks;

namespace libsignalservice.websocket
{
    public class SignalWebSocketMessageReceivedEventArgs
    {
        public byte[]? Message { get; set; }
    }

    public class SignalWebSocketClosedEventArgs
    {
        public ushort Code { get; set; }
        public string? Reason { get; set; }
    }

    public interface ISignalWebSocket : IDisposable
    {
        void Close(ushort code, string reason);
        Task ConnectAsync();
        Task SendMessage(byte[] data);

        event EventHandler<SignalWebSocketClosedEventArgs> Closed;
        event EventHandler<SignalWebSocketMessageReceivedEventArgs> MessageReceived;
    }

    public interface ISignalWebSocketFactory
    {
        ISignalWebSocket CreateSignalWebSocket(Uri uri, CancellationToken? token = null);
    }
}
