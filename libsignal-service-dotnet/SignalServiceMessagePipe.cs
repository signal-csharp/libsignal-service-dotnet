using Google.Protobuf;
using libsignal.push;
using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;

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

namespace libsignalservice
{
    /// <summary>
    /// A SignalServiceMessagePipe represents a dedicated connection
    /// to the Signal Service server, which the server can push messages
    /// down through.
    /// </summary>
    public class SignalServiceMessagePipe
    {
        private const string TAG = "SignalServiceMessagePipe";
        private readonly SignalWebSocketConnection Websocket;
        private readonly CredentialsProvider CredentialsProvider;
        private CancellationToken Token;

        internal SignalServiceMessagePipe(CancellationToken token, SignalWebSocketConnection websocket, CredentialsProvider credentialsProvider)
        {
            this.Token = token;
            this.Websocket = websocket;
            this.CredentialsProvider = credentialsProvider;
            this.Websocket.Connect();
        }

        public void ReadBlocking(IMessagePipeCallback callback)
        {
            WebSocketRequestMessage request = Websocket.ReadRequestBlocking();

            if (IsSignalServiceEnvelope(request))
            {
                SignalServiceMessagePipeMessage message = new SignalServiceEnvelope(request.Body.ToByteArray(), CredentialsProvider.GetSignalingKey());
                WebSocketResponseMessage response = CreateWebSocketResponse(request);
                try
                {
                    callback.OnMessage(message);
                }
                finally
                {
                    if (!Token.IsCancellationRequested)
                    {
                        Websocket.SendResponse(response);
                    }
                }
            }
            else
            {
                Debug.WriteLine("unknown request: {0} {1}", request.Verb, request.Path);
            }
        }

        public SendMessageResponse Send(OutgoingPushMessageList list)
        {
            WebSocketRequestMessage requestmessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.getSecretBytes(sizeof(long)), 0),
                Verb = "PUT",
                Path = $"/v1/messages/{list.getDestination()}",
                Body = ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.toJson(list)))
            };
            requestmessage.Headers.Add("content-type:application/json");
            var t = Websocket.SendRequest(requestmessage);
            t.Wait();
            if (t.IsCompleted)
            {
                var response = t.Result;
                if (response.Item1 < 200 || response.Item1 >= 300)
                {
                    throw new IOException("non-successfull response: " + response.Item1 + " " + response.Item2);
                }
                return JsonUtil.fromJson<SendMessageResponse>(response.Item2);
            }
            else
            {
                throw new IOException("timeout reached while waiting for confirmation");
            }
        }

        public SignalServiceProfile GetProfile(SignalServiceAddress address)
        {
            WebSocketRequestMessage requestMessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.getSecretBytes(sizeof(long)), 0),
                Verb = "GET",
                Path = $"/v1/profile/{address.getNumber()}"
            };

            var t = Websocket.SendRequest(requestMessage);
            t.Wait();
            if (t.IsCompleted)
            {
                var response = t.Result;
                if (response.Item1 < 200 || response.Item1 >= 300)
                {
                    throw new IOException("non-successfull response: " + response.Item1 + " " + response.Item2);
                }
                return JsonUtil.fromJson<SignalServiceProfile>(response.Item2);
            }
            else
            {
                throw new IOException("timeout reached while waiting for profile");
            }
        }

        /// <summary>
        /// Close this connection to the server.
        /// </summary>
        public void Shutdown()
        {
            Websocket.Disconnect();
        }

        private bool IsSignalServiceEnvelope(WebSocketRequestMessage message)
        {
            return message.Verb == "PUT" && message.Path == "/api/v1/message";
        }

        private WebSocketResponseMessage CreateWebSocketResponse(WebSocketRequestMessage request)
        {
            if (IsSignalServiceEnvelope(request))
            {
                return new WebSocketResponseMessage
                {
                    Id = request.Id,
                    Status = 200,
                    Message = "OK"
                };
            }
            else
            {
                return new WebSocketResponseMessage
                {
                    Id = request.Id,
                    Status = 400,
                    Message = "Unknown"
                };
            }
        }

        /// <summary>
        ///    Abstract superclass for messages received via the SignalServiceMessagePipe.
        /// </summary>
        public abstract class SignalServiceMessagePipeMessage
        {

        }

        /// <summary>
        /// A callback interface for the message pipe.
        /// </summary>
        public interface IMessagePipeCallback
        {
            /// <summary>
            /// This message is called for every message received via the pipe.
            /// </summary>
            /// <param name="message">The received message</param>
            void OnMessage(SignalServiceMessagePipeMessage message);
        }
    }
}
