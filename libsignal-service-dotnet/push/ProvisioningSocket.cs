using Coe.WebSocketWrapper;
using libsignalservice.crypto;
using libsignalservice.push;
using libsignalservice.websocket;
using System.Collections.Concurrent;
using System.Threading;

namespace libsignal.push
{
    public class ProvisioningSocket
    {
        private WebSocketWrapper WebSocket;
        private string WsUri;
        private CancellationToken Token;
        private readonly BlockingCollection<byte[]> IncomingRequests = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());

        public ProvisioningSocket(string httpUri, CancellationToken token)
        {
            Token = token;
            WsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + "/v1/websocket/provisioning/";
            WebSocket = new WebSocketWrapper(WsUri, token);
            WebSocket.OnMessage(Connection_OnMessage);
        }

        public ProvisioningUuid GetProvisioningUuid()
        {
            WebSocket.Connect();
            byte[] raw = IncomingRequests.Take(Token);
            return ProvisioningUuid.Parser.ParseFrom(WebSocketMessage.Parser.ParseFrom(raw).Request.Body);
        }

        public ProvisionMessage GetProvisioningMessage(IdentityKeyPair tmpIdentity)
        {
            byte[] raw = IncomingRequests.Take(Token);
            WebSocketMessage msg = WebSocketMessage.Parser.ParseFrom(raw);
            return new ProvisioningCipher(null).Decrypt(tmpIdentity, msg.Request.Body.ToByteArray());
        }

        private void Connection_OnMessage(byte[] obj)
        {
            IncomingRequests.Add(obj);
        }
    }
}
