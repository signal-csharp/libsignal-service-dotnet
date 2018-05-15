using Coe.WebSocketWrapper;
using Google.Protobuf;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace libsignalservice.websocket
{
    internal class SignalWebSocketConnection
    {
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<SignalWebSocketConnection>();
        private static readonly Object obj = new Object();

        private readonly BlockingCollection<WebSocketRequestMessage> IncomingRequests = new BlockingCollection<WebSocketRequestMessage>(new ConcurrentQueue<WebSocketRequestMessage>());
        private readonly ConcurrentDictionary<ulong, Tuple<CountdownEvent, uint, string>> OutgoingRequests = new ConcurrentDictionary<ulong, Tuple<CountdownEvent, uint, string>>();

        private readonly string WsUri;
        private readonly CredentialsProvider CredentialsProvider;
        private readonly string UserAgent;
        private WebSocketWrapper WebSocket;
        private readonly CancellationToken Token;
        private readonly ConnectivityListener Listener;

        internal SignalWebSocketConnection(CancellationToken token, string httpUri, CredentialsProvider credentialsProvider, string userAgent, ConnectivityListener listener)
        {
            Token = token;
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
            Listener = listener;
            if (credentialsProvider.DeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                WsUri = httpUri.Replace("https://", "wss://")
                    .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.User}&password={credentialsProvider.Password}";
            }
            else
            {
                WsUri = httpUri.Replace("https://", "wss://")
                    .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.User}.{credentialsProvider.DeviceId}&password={credentialsProvider.Password}";
            }
            UserAgent = userAgent;
            WebSocket = new WebSocketWrapper(WsUri);
            WebSocket.OnConnect(Connection_OnOpened);
            WebSocket.OnMessage(Connection_OnMessage);
        }

        public async Task Connect(CancellationToken token)
        {
            Listener?.OnConnecting();
            await WebSocket.Connect(token);
        }

        private void Connection_OnOpened()
        {
            Listener?.OnConnecting();
        }

        private void Connection_OnMessage(byte[] obj)
        {
            var msg = WebSocketMessage.Parser.ParseFrom(obj);
            if (msg.Type == WebSocketMessage.Types.Type.Request)
            {
                Logger.LogTrace("Adding request to IncomingRequests");
                IncomingRequests.Add(msg.Request);
            }
            else if (msg.Type == WebSocketMessage.Types.Type.Response)
            {
                Logger.LogTrace("Adding response {0} ({1} {2})", msg.Response.Id, msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray()));
                var t = new Tuple<CountdownEvent, uint, string>(null, msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray()));
                Tuple<CountdownEvent, uint, string> savedRequest;
                OutgoingRequests.TryGetValue(msg.Response.Id, out savedRequest);
                OutgoingRequests.AddOrUpdate(msg.Response.Id, t, (k, v) => t);
                savedRequest.Item1.Signal();
            }
        }

        public void Disconnect()
        {
            Logger.LogWarning("Disconnect is not supported yet");
            throw new NotImplementedException();
        }



        /// <summary>
        /// Gets the next WebSocketRequestMessage from the websocket.
        /// If there are no received messages in the buffer, this method will block until there are, or this connection's token is cancelled.
        /// </summary>
        /// <remarks>
        /// keks
        /// </remarks>
        /// <returns>A WebSocketRequestMessage read from the websocket's pipe</returns>
        public WebSocketRequestMessage ReadRequestBlocking()
        {
            return IncomingRequests.Take(Token);
        }

        /// <summary>
        /// Sends a WebSocketRequestMessage to the Signal server. The returned task will block for a maximum of 10 seconds.
        /// </summary>
        /// <param name="request"></param>
        /// <returns>Returns a task that returns a server response or throws an exception.</returns>
        internal async Task<Tuple<uint, string>> SendRequest(WebSocketRequestMessage request)
        {
            Tuple<CountdownEvent, uint, string> t = new Tuple<CountdownEvent, uint, string>(new CountdownEvent(1), 0, null);
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = request
            };
            OutgoingRequests.AddOrUpdate(request.Id, t, (k, v) => t);
            WebSocket.OutgoingQueue.Add(message.ToByteArray());
            return await Task.Run(() =>
            {
                if (t.Item1.Wait(10 * 1000, Token))
                {
                    var handledTuple = OutgoingRequests[request.Id];
                    return new Tuple<uint, string>(handledTuple.Item2, handledTuple.Item3);
                }
                throw new IOException("wait for confirmation timeout");
            });
        }

        /// <summary>
        /// Sends a WebSocketResponseMessage to the Signal server. This method does not block until the message is actually sent.
        /// </summary>
        /// <param name="response"></param>
        public void SendResponse(WebSocketResponseMessage response)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Response,
                Response = response
            };
            WebSocket.OutgoingQueue.Add(message.ToByteArray());
        }

        private void SendKeepAlive(CancellationToken token, object state)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = new WebSocketRequestMessage
                {
                    Id = KeyHelper.getTime(),
                    Path = "/v1/keepalive",
                    Verb = "GET"
                },
            };
            WebSocket.OutgoingQueue.Add(message.ToByteArray());
        }
    }
}
