using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;

namespace Coe.WebSocketWrapper
{
    public class WebSocketWrapper
    {
        //https://gist.github.com/xamlmonkey/4737291
        public static readonly string TAG = "[WebSocketWrapper] ";

        public BlockingCollection<byte[]> OutgoingQueue = new BlockingCollection<byte[]>(new ConcurrentQueue<byte[]>());
        private Task HandleOutgoing;
        private Task HandleIncoming;

        private const int ReceiveChunkSize = 1024;
        private const int SendChunkSize = 1024;

        private readonly ClientWebSocket _ws;
        private readonly Uri _uri;
        private readonly CancellationToken Token;

        private Action _onConnected;
        private Action<byte[]> _onMessage;

        public WebSocketWrapper(string uri, CancellationToken token)
        {
            _ws = new ClientWebSocket();
            _ws.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
            _uri = new Uri(uri);
            Token = token;
        }

        public void HandleOutgoingWS()
        {
            Debug.WriteLine(TAG + "HandleOutgoingWS started");
            while (!Token.IsCancellationRequested)
            {
                try
                {
                    var buf = OutgoingQueue.Take(Token);
                    _ws.SendAsync(new ArraySegment<byte>(buf, 0, buf.Length), WebSocketMessageType.Binary, true, Token).Wait();
                }
                catch (TaskCanceledException e)
                {
                    Debug.WriteLine(TAG + "HandleOutgoingWS shutting down");
                }
                catch (Exception e)
                {
                    Debug.WriteLine(TAG + "WS SendAsync failed: " + e.Message);
                    //TODO reconnect
                }
            }
            //TODO dispose
            Debug.WriteLine(TAG + "HandleOutgoingWS finished");
        }

        public void HandleIncomingWS()
        {
            Debug.WriteLine(TAG + "HandleIncomingWS started");
            var buffer = new byte[ReceiveChunkSize];
            while (!Token.IsCancellationRequested)
            {
                var message = new MemoryStream();
                WebSocketReceiveResult result;
                try
                {
                    do
                    {
                        result = _ws.ReceiveAsync(new ArraySegment<byte>(buffer), Token).Result;
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, string.Empty, CancellationToken.None).Wait();
                            //TODO reconnect
                        }
                        else
                        {
                            message.Write(buffer, 0, result.Count);
                        }
                    } while (!result.EndOfMessage);
                    CallOnMessage(message.ToArray());
                }
                catch (TaskCanceledException e)
                {
                    Debug.WriteLine(TAG + "HandleIncomingWS shutting down");
                }
                catch (Exception e)
                {
                    Debug.WriteLine(e.Message);
                    Debug.WriteLine(e.StackTrace);
                    //TODO reconnect
                }
            }
            //TODO dispose
            Debug.WriteLine(TAG + "HandleIncomingWS finished");
        }

        /// <summary>
        /// Connects to the WebSocket server.
        /// </summary>
        /// <returns></returns>
        public WebSocketWrapper Connect()
        {
            ConnectAsync();
            return this;
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

        private async void ConnectAsync()
        {
            try
            {
                await _ws.ConnectAsync(_uri, Token);
                HandleOutgoing = Task.Factory.StartNew(HandleOutgoingWS, TaskCreationOptions.LongRunning);
                HandleIncoming = Task.Factory.StartNew(HandleIncomingWS, TaskCreationOptions.LongRunning);
                CallOnConnected();
            }
            catch (Exception e)
            {
                Debug.WriteLine("ConnectAsync crashed.");
                Debug.WriteLine(e.Message);
                Debug.WriteLine(e.StackTrace);
            }
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
