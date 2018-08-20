using Google.Protobuf;
using libsignal.push;
using libsignalservice.messages;
using libsignalservice.profiles;
using libsignalservice.push;
using libsignalservice.util;
using libsignalservice.websocket;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace libsignalservice
{
    /// <summary>
    /// A SignalServiceMessagePipe represents a dedicated connection
    /// to the Signal Service server, which the server can push messages
    /// down through.
    /// </summary>
    public class SignalServiceMessagePipe
    {
        private readonly ILogger Logger = LibsignalLogging.CreateLogger<SignalServiceMessagePipe>();
        private readonly ISignalWebSocketFactory SignalWebSocketFactory;
        private readonly SignalWebSocketConnection Websocket;
        private readonly ICredentialsProvider CredentialsProvider;
        private CancellationToken Token;

        internal SignalServiceMessagePipe(CancellationToken token, SignalWebSocketConnection websocket,
            ICredentialsProvider credentialsProvider, ISignalWebSocketFactory webSocketFactory)
        {
            Logger.LogTrace("SignalServiceMessagePipe()");
            Token = token;
            Websocket = websocket;
            CredentialsProvider = credentialsProvider;
            SignalWebSocketFactory = webSocketFactory;
        }

        /// <summary>
        /// Connect message pipe.
        /// </summary>
        /// <returns>Task</returns>
        public async Task Connect()
        {
            Logger.LogTrace("Connecting to message pipe");
            await Websocket.Connect();
        }

        /// <summary>
        /// Blocks until a message was received, calls the IMessagePipeCallback and confirms the message to the server, unless the pipe's token is cancelled.
        /// </summary>
        /// <param name="callback"></param>
        public async Task ReadBlocking(IMessagePipeCallback callback)
        {
            Logger.LogTrace("ReadBlocking()");
            WebSocketRequestMessage request = Websocket.ReadRequestBlocking();

            if (IsSignalServiceEnvelope(request))
            {
                SignalServiceMessagePipeMessage message = new SignalServiceEnvelope(request.Body.ToByteArray(), CredentialsProvider.SignalingKey);
                WebSocketResponseMessage response = CreateWebSocketResponse(request);
                Logger.LogDebug("Calling callback with message {0}", request.Id);
			    await callback.OnMessage(message);
                if (!Token.IsCancellationRequested)
                {
                    Logger.LogDebug("Confirming message {0}", request.Id);
                    Websocket.SendResponse(response);
                }
                
            }
            else if (IsPipeEmptyMessage(request))
            {
                Logger.LogInformation("Calling callback with SignalServiceMessagePipeEmptyMessage");
                await callback.OnMessage(new SignalServiceMessagePipeEmptyMessage());
            }
            else
            {
                Logger.LogWarning("Unknown request: {0} {1}", request.Verb, request.Path);
            }
        }

        /// <summary>
        /// Sends a message through the pipe. Blocks until delivery is confirmed or throws an IOException if a timeout occurs.
        /// </summary>
        /// <param name="list"></param>
        /// <returns></returns>
        public async Task<SendMessageResponse> Send(OutgoingPushMessageList list)
        {
            Logger.LogTrace("Send()");
            WebSocketRequestMessage requestmessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "PUT",
                Path = $"/v1/messages/{list.Destination}",
                Body = ByteString.CopyFrom(Encoding.UTF8.GetBytes(JsonUtil.ToJson(list)))
            };
            requestmessage.Headers.Add("content-type:application/json");
            var sendTask = (await Websocket.SendRequest(requestmessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(10*1000, timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (Status, Body) = sendTask.Result;
                if (Status < 200 || Status >= 300)
                {
                    throw new IOException("non-successfull response: " + Status);
                }
                if (Util.IsEmpty(Body))
                    return new SendMessageResponse(false);
                return JsonUtil.FromJson<SendMessageResponse>(Body);
            }
            else
            {
                Logger.LogError("Sending message {0} failed: timeout", requestmessage.Id);
                throw new IOException("timeout reached while waiting for confirmation");
            }
        }

        /// <summary>
        /// Fetches a profile from the server. Blocks until the response arrives or a timeout occurs.
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        public async Task<SignalServiceProfile> GetProfile(SignalServiceAddress address)
        {
            Logger.LogTrace("GetProfile()");
            WebSocketRequestMessage requestMessage = new WebSocketRequestMessage()
            {
                Id = BitConverter.ToUInt64(Util.GetSecretBytes(sizeof(long)), 0),
                Verb = "GET",
                Path = $"/v1/profile/{address.E164number}"
            };

            var sendTask = (await Websocket.SendRequest(requestMessage)).Task;
            var timerCancelSource = new CancellationTokenSource();
            if (await Task.WhenAny(sendTask, Task.Delay(10 * 1000, timerCancelSource.Token)) == sendTask)
            {
                timerCancelSource.Cancel();
                var (Status, Body) = sendTask.Result;
                if (Status < 200 || Status >= 300)
                {
                    throw new IOException("non-successfull response: " + Status);
                }
                return JsonUtil.FromJson<SignalServiceProfile>(Body);
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

        private bool IsPipeEmptyMessage(WebSocketRequestMessage message)
        {
            return message.Verb == "PUT" && message.Path == "/api/v1/queue/empty";
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
        /// A Message that indicates that the queue is empty.
        /// </summary>
        public class SignalServiceMessagePipeEmptyMessage: SignalServiceMessagePipeMessage
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
            Task OnMessage(SignalServiceMessagePipeMessage message);
        }
    }
}
