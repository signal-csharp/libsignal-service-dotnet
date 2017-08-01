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

        private volatile ClientWebSocket WebSocket;
        private readonly Uri _uri;
        private readonly CancellationToken Token;
        private object ReconnectLock = new object();

        private Action _onConnected;
        private Action<byte[]> _onMessage;

        public WebSocketWrapper(string uri, CancellationToken token)
        {
            CreateSocket();
            _uri = new Uri(uri);
            Token = token;
        }

        private void CreateSocket()
        {
            WebSocket = new ClientWebSocket();
            WebSocket.Options.KeepAliveInterval = TimeSpan.FromSeconds(20);
        }

        public void HandleOutgoingWS()
        {
            Debug.WriteLine(TAG + "HandleOutgoingWS: Running");
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
                catch (TaskCanceledException e)
                {
                    Debug.WriteLine(TAG + "HandleOutgoingWS: Shutting down");
                }
                catch (Exception e)
                {
                    Debug.WriteLine(TAG + "HandleOutgoingWS: Send failed (" + e.Message + ")");
                    Debug.WriteLine(TAG + "HandleOutgoingWS: Reconnecting");
                    Reconnect();
                }
            }
            //TODO dispose
            Debug.WriteLine(TAG + "HandleOutgoingWS: Finished");
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
                catch (Exception e)
                {
                    Debug.WriteLine("Reconnect: Could not close websocket gracefully (" + e.Message + ")");
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
                        Debug.WriteLine("Reconnect: Failed to open websocket connection (" + e.Message + ")");
                        var delay_length = 15;
                        if (tries > 20)
                            delay_length = 60 * 5;
                        else if (tries > 10)
                            delay_length = 60;
                        else if (tries > 5)
                            delay_length = 30;
                        Task.Delay(1000 * delay_length, Token).Wait();
                    }
                }
            }
            Debug.WriteLine("Reconnect: Successfully reconnected to the server");
        }

        public void HandleIncomingWS()
        {
            Debug.WriteLine(TAG + "HandleIncomingWS: Running");
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
                catch (TaskCanceledException e)
                {
                    Debug.WriteLine(TAG + "HandleIncomingWS: Shutting down");
                }
                catch (Exception e)
                {
                    Debug.WriteLine(TAG + "HandleIncomingWS: Recv failed (" + e.Message + ")");
                    Debug.WriteLine(TAG + "HandleIncomingWS: Reconnecting");
                    Reconnect();
                }
            }
            //TODO dispose
            Debug.WriteLine(TAG + "HandleIncomingWS: Finished");
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
                await WebSocket.ConnectAsync(_uri, Token);
                CallOnConnected();
            }
            catch (Exception e)
            {
                Debug.WriteLine("ConnectAsync crashed.");
                Debug.WriteLine(e.Message);
                Debug.WriteLine(e.StackTrace);
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