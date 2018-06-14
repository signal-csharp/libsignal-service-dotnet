using Coe.WebSocketWrapper;
using libsignalservice.crypto;
using libsignalservice.push;
using libsignalservice.websocket;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace libsignal.push
{
    internal class ProvisioningSocket
    {
        private ISignalWebSocket SignalWebSocket;
        private readonly string WsUri;
        private readonly BlockingCollection<Stream> IncomingRequests = new BlockingCollection<Stream>(new ConcurrentQueue<Stream>());

        public ProvisioningSocket(string httpUri, ISignalWebSocketFactory webSocketFactory, CancellationToken token)
        {
            WsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + "/v1/websocket/provisioning/";
            SignalWebSocket = webSocketFactory.CreateSignalWebSocket(token, new Uri(WsUri));
            SignalWebSocket.MessageReceived += SignalWebSocket_MessageReceived;
        }

        private void SignalWebSocket_MessageReceived(object sender, SignalWebSocketMessageReceivedEventArgs e)
        {
            IncomingRequests.Add(e.Message);
        }

        private async Task<Stream> TakeAsync(CancellationToken token)
        {
            return await Task.Run(() =>
            {
                return IncomingRequests.Take(token); //TODO don't block
            });
        }

        public async Task<ProvisioningUuid> GetProvisioningUuid(CancellationToken token)
        {
            await SignalWebSocket.ConnectAsync();
            Stream raw = await TakeAsync(token);
            return ProvisioningUuid.Parser.ParseFrom(WebSocketMessage.Parser.ParseFrom(raw).Request.Body);
        }

        public async Task<ProvisionMessage> GetProvisioningMessage(CancellationToken token, IdentityKeyPair tmpIdentity)
        {
            Stream raw = await TakeAsync(token);
            WebSocketMessage msg = WebSocketMessage.Parser.ParseFrom(raw);
            return new ProvisioningCipher(null).Decrypt(tmpIdentity, msg.Request.Body.ToByteArray());
        }
    }
}
