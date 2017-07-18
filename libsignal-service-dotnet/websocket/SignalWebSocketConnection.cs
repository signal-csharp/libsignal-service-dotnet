using Coe.WebSocketWrapper;
using Google.Protobuf;
using libsignal.util;
using libsignalservice.push;
using libsignalservice.util;

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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace libsignalservice.websocket
{
    public class SignalWebSocketConnection
    {
        private static readonly string TAG = "WebSocketConnection";
        private static readonly int KEEPALIVE_TIMEOUT_SECONDS = 55;
        private static readonly Object obj = new Object();

        private readonly BlockingCollection<WebSocketRequestMessage> IncomingRequests = new BlockingCollection<WebSocketRequestMessage>(new ConcurrentQueue<WebSocketRequestMessage>());
        private readonly ConcurrentDictionary<ulong, Tuple<CountdownEvent, uint, string>> OutgoingRequests = new ConcurrentDictionary<ulong, Tuple<CountdownEvent, uint, string>>();

        private readonly string WsUri;
        private readonly CredentialsProvider CredentialsProvider;
        private readonly string UserAgent;
        private WebSocketWrapper WebSocket;
        private CancellationToken Token;

        public SignalWebSocketConnection(CancellationToken token, string httpUri, CredentialsProvider credentialsProvider, string userAgent)
        {
            Token = token;
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
            if (credentialsProvider.GetDeviceId() == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                WsUri = httpUri.Replace("https://", "wss://")
                    .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.GetUser()}&password={credentialsProvider.GetPassword()}";
            }
            else
            {
                WsUri = httpUri.Replace("https://", "wss://")
                    .Replace("http://", "ws://") + $"/v1/websocket/?login={credentialsProvider.GetUser()}.{credentialsProvider.GetDeviceId()}&password={credentialsProvider.GetPassword()}";
            }
            UserAgent = userAgent;
            WebSocket = new WebSocketWrapper(WsUri, token);
            WebSocket.OnConnect(Connection_OnOpened);
            WebSocket.OnMessage(Connection_OnMessage);
        }

        public void Connect()
        {
            Debug.WriteLine("WebSocketConnection: connect()...");
            WebSocket.Connect();
        }

        private void Connection_OnOpened()
        {
            Debug.WriteLine("WebSocketConnection: opened!");
        }

        private void Connection_OnMessage(byte[] obj)
        {
            var msg = WebSocketMessage.Parser.ParseFrom(obj);
            if (msg.Type == WebSocketMessage.Types.Type.Request)
            {
                IncomingRequests.Add(msg.Request);
            }
            else if (msg.Type == WebSocketMessage.Types.Type.Response)
            {
                Debug.WriteLine("SignalWebSocketConnection received response id={0}, message={1}, status={2} body={3}", msg.Response.Id, msg.Response.Message, msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray()));
                var t = new Tuple<CountdownEvent, uint, string>(null, msg.Response.Status, Encoding.UTF8.GetString(msg.Response.Body.ToByteArray()));
                Tuple<CountdownEvent, uint, string> savedRequest;
                OutgoingRequests.TryGetValue(msg.Response.Id, out savedRequest);
                OutgoingRequests.AddOrUpdate(msg.Response.Id, t, (k, v) => t);
                savedRequest.Item1.Signal();
            }
        }

        public void Disconnect()
        {
            Debug.WriteLine("WebSocketConnection disconnect()...");
            throw new NotImplementedException();
        }

        public LinkedList<WebSocketRequestMessage> readRequests()
        {
            LinkedList<WebSocketRequestMessage> requests = new LinkedList<WebSocketRequestMessage>();

            WebSocketRequestMessage item;
            while (IncomingRequests.TryTake(out item))
            {
                requests.AddLast(item);
            }
            if (requests.Count > 0)
            {
                return requests;
            }
            requests.AddLast(IncomingRequests.Take(Token));
            return requests;
        }

        public async Task<Tuple<uint, string>> SendRequest(WebSocketRequestMessage request)
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

        public void SendResponse(WebSocketResponseMessage response)
        {
            WebSocketMessage message = new WebSocketMessage
            {
                Type = WebSocketMessage.Types.Type.Response,
                Response = response
            };
            WebSocket.OutgoingQueue.Add(message.ToByteArray());
        }

        private void sendKeepAlive(CancellationToken token, object state)
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
            WebSocket.OutgoingQueue.Add(message.ToByteArray());
        }
    }
}
