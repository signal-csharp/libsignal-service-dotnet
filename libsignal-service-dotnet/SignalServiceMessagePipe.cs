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
using System.Diagnostics;
using libsignalservice.messages;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
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
        private readonly SignalWebSocketConnection websocket;
        private readonly CredentialsProvider credentialsProvider;

        public SignalServiceMessagePipe(SignalWebSocketConnection websocket, CredentialsProvider credentialsProvider)
        {
            this.websocket = websocket;
            this.credentialsProvider = credentialsProvider;
            this.websocket.Connect();
        }

        public void Read(MessagePipeCallback callback)
        {
            WebSocketRequestMessage request = websocket.readRequest();
            if(request != null)
            {
                var response = createWebSocketResponse(request);

                try
                {
                    if (isSignalServiceEnvelope(request))
                    {
                        var envelope = new SignalServiceEnvelope(request.Body.ToByteArray(), credentialsProvider.GetSignalingKey());
                        if (callback != null)
                        {
                            callback.onMessage(envelope);
                        }
                    }
                }
                finally
                {
                    websocket.sendResponse(response);
                }
            }
        }

        public SendMessageResponse send(OutgoingPushMessageList list)
        {

            throw new NotImplementedException();
            //try
            //{
            //    WebSocketRequestMessage requestmessage = WebSocketRequestMessage.CreateBuilder()
            //        .SetId((ulong)CryptographicBuffer.GenerateRandomNumber())
            //        .SetVerb("PUT")
            //        .SetPath($"/v1/messages/{list.getDestination()}")
            //        .AddHeaders("content-type:application/json")
            //        .SetBody(ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.toJson(list))))
            //        .Build();

            //}
        }

        /// <summary>
        /// Close this connection to the server.
        /// </summary>
        public void shutdown()
        {
            websocket.Disconnect();
        }

        private bool isSignalServiceEnvelope(WebSocketRequestMessage message)
        {
            return "PUT".Equals(message.Verb) && "/api/v1/message".Equals(message.Path);
        }

        private WebSocketResponseMessage createWebSocketResponse(WebSocketRequestMessage request)
        {
            if (isSignalServiceEnvelope(request))
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
      
        /**
         * For receiving a callback when a new message has been
         * received.
         */
        public interface MessagePipeCallback
        {
            void onMessage(SignalServiceEnvelope envelope);
        }

        private class NullMessagePipeCallback : MessagePipeCallback
        {
            public void onMessage(SignalServiceEnvelope envelope) { }
        }
    }
}
