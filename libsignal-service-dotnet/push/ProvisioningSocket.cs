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
        private readonly BlockingCollection<WebSocketMessage> IncomingRequests = new BlockingCollection<WebSocketMessage>(new ConcurrentQueue<WebSocketMessage>());

        public ProvisioningSocket(string httpUri, ISignalWebSocketFactory webSocketFactory, CancellationToken token)
        {
            WsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + "/v1/websocket/provisioning/";
            SignalWebSocket = webSocketFactory.CreateSignalWebSocket(token, new Uri(WsUri));
            SignalWebSocket.MessageReceived += SignalWebSocket_MessageReceived;
        }

        private void SignalWebSocket_MessageReceived(object sender, SignalWebSocketMessageReceivedEventArgs e)
        {
            var msg = WebSocketMessage.Parser.ParseFrom(e.Message);
            IncomingRequests.Add(msg);
        }

        private async Task<WebSocketMessage> TakeAsync(CancellationToken token)
        {
            return await Task.Run(() =>
            {
                return IncomingRequests.Take(token); //TODO don't block
            });
        }

        public async Task<ProvisioningUuid> GetProvisioningUuid(CancellationToken token)
        {
            await SignalWebSocket.ConnectAsync();
            var msg = await TakeAsync(token);
            return ProvisioningUuid.Parser.ParseFrom(msg.Request.Body);
        }

        public async Task<ProvisionMessage> GetProvisioningMessage(CancellationToken token, IdentityKeyPair tmpIdentity)
        {
            var msg = await TakeAsync(token);
            return new ProvisioningCipher(null).Decrypt(tmpIdentity, msg.Request.Body.ToByteArray());
        }
    }
}
