using libsignalservice;
using libsignalservice.push.exceptions;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace Coe.WebSocketWrapper
{
    internal class WebSocketWrapper
    {
        //https://gist.github.com/xamlmonkey/4737291
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<WebSocketWrapper>();
        public BlockingCollection<byte[]> OutgoingQueue = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());
        private Task HandleOutgoing;
        private Task HandleIncoming;
        private const int ReceiveChunkSize = 1024;
        private volatile ClientWebSocket WebSocket;
        private readonly Uri _uri;
        private readonly CancellationToken Token;
        private object ReconnectLock = new object();
        private Action _onConnected;
        private Action<byte[]> _onMessage;

        internal WebSocketWrapper(string uri, CancellationToken token)
        {
            CreateSocket();
            _uri = new Uri(uri);
            Token = token;
        }

        private void CreateSocket()
        {
            WebSocket = new ClientWebSocket();
            WebSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(30);
        }

        public void HandleOutgoingWS()
        {
            Logger.LogTrace("HandleOutgoingWS()");
            byte[] buf = null;
            while (!Token.IsCancellationRequested)
            {
                try
                {
                    if (buf == null)
                        buf = OutgoingQueue.Take(Token);
                    WebSocket.SendAsync(new ArraySegment<byte>(buf, 0, buf.Length), WebSocketMessageType.Binary, true, Token).Wait();
                    buf = null; //set to null so we do not retry the same block
                }
                catch (TaskCanceledException)
                {
                    Logger.LogDebug("HandleOutgoingWS task shutting down");
                }
                catch (Exception e)
                {
                    Logger.LogWarning("HandleOutgoingWS: Send failed ({0})", e.Message);
                    Logger.LogInformation("HandleOutgoingWS reconnecting");
                    Reconnect();
                }
            }
            //TODO dispose
            Logger.LogTrace("HandleOutgoingWS task finished");
        }

        public void Reconnect()
        {
            lock (ReconnectLock)
            {
                if (WebSocket.State == WebSocketState.Open)
                    return;

                var tries = 0;
                try
                {
                    WebSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, "goodbye", Token).Wait();
                }
                catch (Exception)
                {
                    Logger.LogTrace("could not close old websocket gracefully");
                }
                while (true)
                {
                    try
                    {
                        if (Token.IsCancellationRequested)
                            return;
                        tries++;
                        CreateSocket();
                        WebSocket.ConnectAsync(_uri, Token).Wait();
                        break;
                    }
                    catch (Exception e)
                    {
                        var delay_length = 15;
                        if (tries > 20)
                            delay_length = 60 * 5;
                        else if (tries > 10)
                            delay_length = 60;
                        else if (tries > 5)
                            delay_length = 30;
                        Logger.LogWarning("Failed to reconnect ({0}). Retrying in {1} seconds", e.Message, delay_length);
                        Task.Delay(1000 * delay_length, Token).Wait();
                    }
                }
            }
            Logger.LogInformation("Successfully reconnected to the server");
        }

        public void HandleIncomingWS()
        {
            Logger.LogTrace("HandleIncomingWS");
            var buffer = new byte[ReceiveChunkSize];
            while (!Token.IsCancellationRequested)
            {
                var message = new MemoryStream();
                WebSocketReceiveResult result;
                try
                {
                    do
                    {
                        result = WebSocket.ReceiveAsync(new ArraySegment<byte>(buffer), Token).Result;
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            WebSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None).Wait();
                            throw new Exception("Got a close message requesting reconnect");
                        }
                        else
                        {
                            message.Write(buffer, 0, result.Count);
                        }
                    } while (!result.EndOfMessage);
                    CallOnMessage(message.ToArray());
                }
                catch (TaskCanceledException)
                {
                    Logger.LogDebug("HandleIncomingWS shutting down");
                }
                catch (Exception e)
                {
                    Logger.LogWarning("HandleIncomingWS recv failed ({0})", e.Message);
                    Reconnect();
                }
            }
            //TODO dispose
            Logger.LogInformation("HandleIncomingWS finished");
        }

        /// <summary>
        /// Set the Action to call when the connection has been established.
        /// </summary>
        /// <param name="onConnect">The Action to call.</param>
        /// <returns></returns>
        public WebSocketWrapper OnConnect(Action onConnect)
        {
            _onConnected = onConnect;
            return this;
        }

        /// <summary>
        /// Set the Action to call when a messages has been received.
        /// </summary>
        /// <param name="onMessage">The Action to call.</param>
        /// <returns></returns>
        public void OnMessage(Action<byte[]> onMessage)
        {
            _onMessage = onMessage;
        }

        public void Connect()
        {
            Logger.LogTrace("Connect()");
            try
            {
                lock (ReconnectLock)
                {
                    WebSocket.ConnectAsync(_uri, Token).Wait();
                    CallOnConnected();
                }
            }
            catch (Exception e)
            {
                if(e.InnerException?.InnerException?.Message == "Forbidden")
                {
                    Logger.LogCritical("Server rejected authentication attempt");
                    throw new AuthorizationFailedException("OWS server rejected authorization.");
                }
                Logger.LogWarning("Connect could not connect to the server");
            }
            HandleOutgoing = Task.Factory.StartNew(HandleOutgoingWS, TaskCreationOptions.LongRunning);
            HandleIncoming = Task.Factory.StartNew(HandleIncomingWS, TaskCreationOptions.LongRunning);
        }

        private void CallOnMessage(byte[] result)
        {
            _onMessage?.Invoke(result);
        }

        private void CallOnConnected()
        {
            _onConnected?.Invoke();
        }
    }
}