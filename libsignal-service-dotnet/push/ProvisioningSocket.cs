using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using libsignalservice.crypto;
using libsignalservice.push;
using libsignalservice.websocket;

namespace libsignal.push
{
    internal class ProvisioningSocket
    {
        private ISignalWebSocket signalWebSocket;
        private readonly string wsUri;
        private readonly BlockingCollection<WebSocketMessage> incomingRequests = new BlockingCollection<WebSocketMessage>(new ConcurrentQueue<WebSocketMessage>());

        public ProvisioningSocket(string httpUri, ISignalWebSocketFactory webSocketFactory, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            wsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + "/v1/websocket/provisioning/";
            signalWebSocket = webSocketFactory.CreateSignalWebSocket(new Uri(wsUri), token);
            signalWebSocket.MessageReceived += SignalWebSocket_MessageReceived;
        }

        private void SignalWebSocket_MessageReceived(object sender, SignalWebSocketMessageReceivedEventArgs e)
        {
            var msg = WebSocketMessage.Parser.ParseFrom(e.Message);
            incomingRequests.Add(msg);
        }

        private async Task<WebSocketMessage> TakeAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            return await Task.Run(() =>
            {
                return incomingRequests.Take(token.Value); //TODO don't block
            });
        }

        public async Task<ProvisioningUuid> GetProvisioningUuidAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await signalWebSocket.ConnectAsync();
            var msg = await TakeAsync(token);
            return ProvisioningUuid.Parser.ParseFrom(msg.Request.Body);
        }

        public async Task<ProvisionMessage> GetProvisioningMessageAsync(IdentityKeyPair tmpIdentity, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            var msg = await TakeAsync(token);
            return new ProvisioningCipher(null!).Decrypt(tmpIdentity, msg.Request.Body.ToByteArray());
        }
    }
}
