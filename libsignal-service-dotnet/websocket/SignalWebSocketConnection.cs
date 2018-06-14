using Coe.WebSocketWrapper;
using Google.Protobuf;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
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
        private readonly ConcurrentDictionary<ulong, TaskCompletionSource<(uint, string)>> OutgoingRequests = new ConcurrentDictionary<ulong, TaskCompletionSource<(uint, string)>>();

        private readonly string WsUri;
        private readonly ICredentialsProvider CredentialsProvider;
        private readonly string UserAgent;
        private readonly CancellationToken Token;
        private ISignalWebSocket SignalWebSocket;

        internal SignalWebSocketConnection(CancellationToken token, string httpUri, ICredentialsProvider credentialsProvider,
            string userAgent, ISignalWebSocketFactory webSocketFactory)
        {
            Token = token;
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
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
            SignalWebSocket = webSocketFactory.CreateSignalWebSocket(token, new Uri(WsUri));
            Token.Register(() =>
            {
                SignalWebSocket.Close(1000, "Shutting down");
            });
            SignalWebSocket.MessageReceived += SignalWebSocket_MessageReceived;
        }

        private void SignalWebSocket_MessageReceived(object sender, SignalWebSocketMessageReceivedEventArgs e)
        {
            try
            {
                var msg = WebSocketMessage.Parser.ParseFrom(e.Message);
                if (msg.Type == WebSocketMessage.Types.Type.Request)
                {
                    IncomingRequests.Add(msg.Request);
                }
                else if (msg.Type == WebSocketMessage.Types.Type.Response)
                {
                    OutgoingRequests.TryGetValue(msg.Response.Id, out TaskCompletionSource<(uint, string)> savedRequest);
                    if (savedRequest != null)
                    {
                        savedRequest.SetResult((msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray())));
                    }
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("SignalWebSocket_MessageReceived failed: {0}\n{1}", ex.Message, ex.StackTrace);
            }
        }

        public async Task Connect()
        {
            await SignalWebSocket.ConnectAsync();
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
        internal async Task<TaskCompletionSource<(uint Status, string Body)>> SendRequest(WebSocketRequestMessage request)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = request
            };
            var messageSendResult = new TaskCompletionSource<(uint, string)>();
            OutgoingRequests.AddOrUpdate(request.Id, messageSendResult, (k, v) => messageSendResult);
            await SignalWebSocket.SendMessage(message.ToByteArray());
            return messageSendResult;
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
            SignalWebSocket.SendMessage(message.ToByteArray());
        }

        private void SendKeepAlive(CancellationToken token, object state)
        {
            throw new NotImplementedException();
            /*
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
            WebSocket.OutgoingQueue.Add(message.ToByteArray()); TODO
            */
        }
    }
}
