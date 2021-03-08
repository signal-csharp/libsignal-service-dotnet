using System;
using System.Collections.Concurrent;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignalservice.push;
using libsignalservice.util;
using Microsoft.Extensions.Logging;

namespace libsignalservice.websocket
{
    internal class SignalWebSocketConnection
    {
        private readonly ILogger logger = LibsignalLogging.CreateLogger<SignalWebSocketConnection>();

        private readonly BlockingCollection<WebSocketRequestMessage> incomingRequests = new BlockingCollection<WebSocketRequestMessage>(new ConcurrentQueue<WebSocketRequestMessage>());
        private readonly ConcurrentDictionary<ulong, TaskCompletionSource<(uint, string)>> outgoingRequests = new ConcurrentDictionary<ulong, TaskCompletionSource<(uint, string)>>();

        private readonly string wsUri;
        private readonly ICredentialsProvider? credentialsProvider;
        private readonly string userAgent;
        private readonly CancellationToken token;
        private ISignalWebSocket signalWebSocket;

        internal SignalWebSocketConnection(string httpUri, ICredentialsProvider? credentialsProvider,
            string userAgent, ISignalWebSocketFactory webSocketFactory, CancellationToken? token)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            this.token = token.Value;
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            string uri = httpUri.Replace("https://", "wss://").Replace("http://", "ws://");
            if (credentialsProvider != null)
            {
                string identifier = credentialsProvider.Uuid != null ? credentialsProvider.Uuid.ToString() :
                    credentialsProvider.E164!;
                if (credentialsProvider.DeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID)
                {
                    wsUri = uri + $"/v1/websocket/?login={identifier}&password={credentialsProvider.Password}";
                }
                else
                {
                    wsUri = uri + $"/v1/websocket/?login={identifier}.{credentialsProvider.DeviceId}&password={credentialsProvider.Password}";
                }
            }
            else
            {
                wsUri = uri + "/v1/websocket/";
            }
            this.userAgent = userAgent;
            signalWebSocket = webSocketFactory.CreateSignalWebSocket(new Uri(wsUri), token);
            this.token.Register(() =>
            {
                signalWebSocket.Close(1000, "Shutting down");
            });
            signalWebSocket.MessageReceived += SignalWebSocket_MessageReceived;
        }

        private void SignalWebSocket_MessageReceived(object sender, SignalWebSocketMessageReceivedEventArgs e)
        {
            try
            {
                var msg = WebSocketMessage.Parser.ParseFrom(e.Message);
                if (msg.Type == WebSocketMessage.Types.Type.Request)
                {
                    incomingRequests.Add(msg.Request);
                }
                else if (msg.Type == WebSocketMessage.Types.Type.Response)
                {
                    outgoingRequests.TryGetValue(msg.Response.Id, out TaskCompletionSource<(uint, string)> savedRequest);
                    if (savedRequest != null)
                    {
                        Task.Run(() => {
                            savedRequest.SetResult((msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray())));
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError("SignalWebSocket_MessageReceived failed: {0}\n{1}", ex.Message, ex.StackTrace);
            }
        }

        public async Task Connect()
        {
            await signalWebSocket.ConnectAsync();
        }

        public void Disconnect()
        {
            logger.LogWarning("Disconnect is not supported yet");
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
            return incomingRequests.Take(token);
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
            outgoingRequests.AddOrUpdate(request.Id, messageSendResult, (k, v) => messageSendResult);
            await signalWebSocket.SendMessage(message.ToByteArray());
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
            signalWebSocket.SendMessage(message.ToByteArray());
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
