/** 
* Copyright (C) 2015-2017 smndtrl, golf1052
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Google.Protobuf;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;
using System.Net.WebSockets;

namespace libsignalservice.websocket
{
    public class WebSocketConnection //: WebSocketEventListener
    {
        private static readonly int KEEPALIVE_TIMEOUT_SECONDS = 55;

        private readonly LinkedList<WebSocketRequestMessage> incomingRequests = new LinkedList<WebSocketRequestMessage>();
        private readonly Dictionary<long, Tuple<int, string>> outgoingRequests = new Dictionary<long, Tuple<int, string>>();

        private readonly string wsUri;
        private readonly TrustStore trustStore;
        private readonly CredentialsProvider credentialsProvider;
        private readonly string userAgent;

        private Timer keepAliveTimer;

        ClientWebSocket socket;
        private int attempts;
        private bool connected;

        public event EventHandler Closed;
        //public event TypedEventHandler<WebSocketConnection, WebSocketRequestMessage> MessageReceived;
        public CancellationTokenSource tokenSource = new CancellationTokenSource();

        public WebSocketConnection(string httpUri, TrustStore trustStore, CredentialsProvider credentialsProvider, string userAgent)
        {
            this.trustStore = trustStore;
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            this.attempts = 0;
            this.connected = false;
            this.wsUri = httpUri.Replace("https://", "wss://")
                .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.GetUser()}&password={credentialsProvider.GetPassword()}";
            this.userAgent = userAgent;
        }


        public async Task connect()
        {
            Debug.WriteLine("WSC connect()...");

            if (socket == null)
            {
                socket = new ClientWebSocket();
                if (userAgent != null)
                {
                    socket.Options.SetRequestHeader("X-Signal-Agent", userAgent);
                }

                Uri server = new Uri(wsUri);
                await socket.ConnectAsync(server, tokenSource.Token);
                if (socket != null)
                {
                    attempts = 0;
                    connected = true;
                }
            }
        }

        public async void disconnect()
        {
            Debug.WriteLine("WSC disconnect()...");

            if (socket != null)
            {
                await socket.CloseAsync(WebSocketCloseStatus.NormalClosure,"OK", tokenSource.Token);
                socket = null;
                connected = false;
            }
        }

        public async Task<WebSocketRequestMessage> readRequest(ulong timeoutMillis)
        {
            if (socket == null)
            {
                throw new Exception("Connection closed!");
            }

            ulong startTime = KeyHelper.getTime();

            while (socket != null && incomingRequests.Count == 0 && elapsedTime(startTime) < timeoutMillis)
            {
                await Task.Delay(1000); //Math.Max(1, timeoutMillis - elapsedTime(startTime)); TODO
            }

            if (incomingRequests.Count == 0 && socket == null) throw new Exception("Connection closed!");
            else if (incomingRequests.Count == 0) throw new TimeoutException("Timeout exceeded");
            else
            {
                WebSocketRequestMessage message = incomingRequests.First.Value;
                incomingRequests.RemoveFirst();
                return message;
            }
        }

        public async Task<Tuple<int, string>> sendRequest(WebSocketRequestMessage request)
        {
            if (socket == null || !connected)
            {
                throw new IOException("No connection!");
            }

            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Request,
                Request = request
            };

            Tuple<int, string> empty = new Tuple<int, string>(0, string.Empty);
            outgoingRequests.Add((long)request.Id, empty);

            await socket.SendAsync(new ArraySegment<byte>(message.ToByteArray()), WebSocketMessageType.Binary, false, tokenSource.Token);
            return empty;
        }

        public async Task sendResponse(WebSocketResponseMessage response)
        {
            if (socket == null)
            {
                throw new Exception("Connection closed!");
            }

            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Response,
                Response = response
            };

            await socket.SendAsync(new ArraySegment<byte>(message.ToByteArray()), WebSocketMessageType.Binary, false, tokenSource.Token);
        }

        private async void sendKeepAlive(object state)
        {
            if (socket != null)
            {
                Debug.WriteLine("keepAlive");
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
                await socket.SendAsync(new ArraySegment<byte>(message.ToByteArray()), WebSocketMessageType.Binary, false, tokenSource.Token);
            }
        }

        private ulong elapsedTime(ulong startTime)
        {
            return KeyHelper.getTime() - startTime;
        } 

        public void shutdown()
        {
            //stop.set(true);
        }
    }
}
