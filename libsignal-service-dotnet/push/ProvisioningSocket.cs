using Coe.WebSocketWrapper;
using libsignalservice.crypto;
using libsignalservice.push;
using libsignalservice.websocket;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace libsignal.push
{
    internal class ProvisioningSocket
    {
        private WebSocketWrapper WebSocket;
        private string WsUri;
        private readonly BlockingCollection<byte[]> IncomingRequests = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());

        public ProvisioningSocket(string httpUri)
        {
            WsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + "/v1/websocket/provisioning/";
            WebSocket = new WebSocketWrapper(WsUri);
            WebSocket.OnMessage(Connection_OnMessage);
        }

        private async Task<byte[]> TakeAsync(CancellationToken token)
        {
            return await Task.Run(() =>
            {
                return IncomingRequests.Take(token); //TODO don't block
            });
        }

        public async Task<ProvisioningUuid> GetProvisioningUuid(CancellationToken token)
        {
            await WebSocket.Connect(token);
            byte[] raw = await TakeAsync(token);
            return ProvisioningUuid.Parser.ParseFrom(WebSocketMessage.Parser.ParseFrom(raw).Request.Body);
        }

        public async Task<ProvisionMessage> GetProvisioningMessage(CancellationToken token, IdentityKeyPair tmpIdentity)
        {
            byte[] raw = await TakeAsync(token);
            WebSocketMessage msg = WebSocketMessage.Parser.ParseFrom(raw);
            return new ProvisioningCipher(null).Decrypt(tmpIdentity, msg.Request.Body.ToByteArray());
        }

        private void Connection_OnMessage(byte[] obj)
        {
            IncomingRequests.Add(obj);
        }
    }
}
