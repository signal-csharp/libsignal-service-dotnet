using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignaldotnet.push.http;
using libsignalservice.configuration;
using libsignalservice.contacts.entities;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.profiles;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using libsignalservicedotnet.push;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    public class PushServiceSocket
    {
        private static readonly string CREATE_ACCOUNT_SMS_PATH = "/v1/accounts/sms/code/{0}";
        private static readonly string CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/{0}";
        private static readonly string VERIFY_ACCOUNT_CODE_PATH = "/v1/accounts/code/{0}";
        private static readonly string REGISTER_GCM_PATH = "/v1/accounts/gcm/";
        private static readonly string TURN_SERVER_INFO = "/v1/accounts/turn";
        private static readonly string SET_ACCOUNT_ATTRIBUTES = "/v1/accounts/attributes";
        private static readonly string PIN_PATH = "/v1/accounts/pin/";

        private static readonly string PREKEY_METADATA_PATH = "/v2/keys/";
        private static readonly string PREKEY_PATH = "/v2/keys/{0}";
        private static readonly string PREKEY_DEVICE_PATH = "/v2/keys/{0}/{1}";
        private static readonly string SIGNED_PREKEY_PATH = "/v2/keys/signed";

        private static readonly string PROVISIONING_CODE_PATH = "/v1/devices/provisioning/code";
        private static readonly string PROVISIONING_MESSAGE_PATH = "/v1/provisioning/{0}";
        private static readonly string DEVICE_PATH = "/v1/devices/{0}";

        private static readonly string DIRECTORY_TOKENS_PATH = "/v1/directory/tokens";
        private static readonly string DIRECTORY_VERIFY_PATH = "/v1/directory/{0}";
        private static readonly string DIRECTORY_AUTH_PATH = "/v1/directory/auth";
        private static readonly string MESSAGE_PATH = "/v1/messages/{0}";
        private static readonly string SENDER_ACK_MESSAGE_PATH = "/v1/messages/{0}/{1}";
        private static readonly string UUID_ACK_MESSAGE_PATH     = "/v1/messages/uuid/{0}";
        private static readonly string ATTACHMENT_PATH = "/v1/attachments/{0}";

        private static readonly string PROFILE_PATH = "/v1/profile/%s";

        private static readonly string SENDER_CERTIFICATE_PATH = "/v1/certificate/delivery";

        private readonly ILogger Logger = LibsignalLogging.CreateLogger<PushServiceSocket>();
        private readonly SignalServiceConfiguration SignalConnectionInformation;
        private readonly ICredentialsProvider CredentialsProvider;
        private readonly string UserAgent;

        public PushServiceSocket(SignalServiceConfiguration serviceUrls, ICredentialsProvider credentialsProvider, string userAgent)
        {
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
            SignalConnectionInformation = serviceUrls;
        }

        public async Task<bool> CreateAccount(CancellationToken token, bool voice)
        {
            string path = voice ? CREATE_ACCOUNT_VOICE_PATH : CREATE_ACCOUNT_SMS_PATH;
            await MakeServiceRequestAsync(token, string.Format(path, CredentialsProvider.User), "GET", null);
            return true;
        }

        public async Task<bool> VerifyAccountCode(CancellationToken token, string verificationCode, string signalingKey, uint registrationId, bool fetchesMessages, string pin,
            byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess)
        {
            AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin, unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
            await MakeServiceRequestAsync(token, string.Format(VERIFY_ACCOUNT_CODE_PATH, verificationCode), "PUT", JsonUtil.ToJson(signalingKeyEntity));
            return true;
        }

        public async Task<bool> SetAccountAttributes(CancellationToken token, string signalingKey, uint registrationId, bool fetchesMessages, string pin,
            byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess)
        {
            AccountAttributes accountAttributesEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin, unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
            await MakeServiceRequestAsync(token, SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.ToJson(accountAttributesEntity));
            return true;
        }

        public async Task<int> FinishNewDeviceRegistration(CancellationToken token, String code, String signalingKey, bool supportsSms, bool fetchesMessages, int registrationId, String deviceName)
        {
            ConfirmCodeMessage javaJson = new ConfirmCodeMessage(signalingKey, supportsSms, fetchesMessages, registrationId, deviceName);
            string json = JsonUtil.ToJson(javaJson);
            string responseText = await MakeServiceRequestAsync(token, string.Format(DEVICE_PATH, code), "PUT", json);
            DeviceId response = JsonUtil.FromJson<DeviceId>(responseText);
            return response.NewDeviceId;
        }

        public async Task<string> GetNewDeviceVerificationCode(CancellationToken token)// throws IOException
        {
            string responseText = await MakeServiceRequestAsync(token, PROVISIONING_CODE_PATH, "GET", null);
            return JsonUtil.FromJson<DeviceCode>(responseText).VerificationCode;
        }

        public async Task<bool> SendProvisioningMessage(CancellationToken token, string destination, byte[] body)// throws IOException
        {
            await MakeServiceRequestAsync(token, string.Format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                    JsonUtil.ToJson(new ProvisioningMessage(Base64.EncodeBytes(body))));
            return true;
        }

        public async Task<List<DeviceInfo>> GetDevices(CancellationToken token)// throws IOException
        {
            string responseText = await MakeServiceRequestAsync(token, string.Format(DEVICE_PATH, ""), "GET", null);
            return JsonUtil.FromJson<DeviceInfoList>(responseText).Devices;
        }

        public async Task<bool> RemoveDevice(CancellationToken token, long deviceId)// throws IOException
        {
            await MakeServiceRequestAsync(token, string.Format(DEVICE_PATH, deviceId), "DELETE", null);
            return true;
        }

        public async Task RegisterGcmId(CancellationToken token, String gcmRegistrationId)
        {
            GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
            await MakeServiceRequestAsync(token, REGISTER_GCM_PATH, "PUT", JsonUtil.ToJson(registration));
        }

        public async Task UnregisterGcmId(CancellationToken token)
        {
            await MakeServiceRequestAsync(token, REGISTER_GCM_PATH, "DELETE", null);
        }

        public async Task SetPin(CancellationToken token, string pin)
        {
            RegistrationLock accountLock = new RegistrationLock(pin);
            await MakeServiceRequestAsync(token, PIN_PATH, "PUT", JsonUtil.ToJson(accountLock));
        }

        public async Task RemovePin(CancellationToken token)
        {
            await MakeServiceRequestAsync(token, PIN_PATH, "PUT", null);
        }

        public async Task<byte[]> GetSenderCertificate(CancellationToken token)
        {
            string responseText = await MakeServiceRequestAsync(token, SENDER_CERTIFICATE_PATH, "GET", null);
            return JsonUtil.FromJson<SenderCertificate>(responseText).GetUnidentifiedCertificate();
        }

        public async Task<SendMessageResponse> SendMessage(CancellationToken token, OutgoingPushMessageList bundle, UnidentifiedAccess? unidentifiedAccess)
        {
            try
            {
                string responseText = await MakeServiceRequestAsync(token, string.Format(MESSAGE_PATH, bundle.Destination), "PUT", JsonUtil.ToJson(bundle), unidentifiedAccess);
                return JsonUtil.FromJson<SendMessageResponse>(responseText);
            }
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(bundle.Destination, nfe);
            }
        }

        public async Task<List<SignalServiceEnvelopeEntity>> GetMessages(CancellationToken token)// throws IOException
        {
            string responseText = await MakeServiceRequestAsync(token, string.Format(MESSAGE_PATH, ""), "GET", null);
            return JsonUtil.FromJson<SignalServiceEnvelopeEntityList>(responseText).Messages;
        }

        public async Task AcknowledgeMessage(CancellationToken token, string sender, ulong timestamp)// throws IOException
        {
            await MakeServiceRequestAsync(token, string.Format(SENDER_ACK_MESSAGE_PATH, sender, timestamp), "DELETE", null);
        }

        public async Task AcknowledgeMessage(CancellationToken token, string uuid)
        {
            await MakeServiceRequestAsync(token, string.Format(UUID_ACK_MESSAGE_PATH, uuid), "DELETE", null);
        }

    public async Task<bool> RegisterPreKeys(CancellationToken token, IdentityKey identityKey, SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> records)
        //throws IOException
        {
            List<PreKeyEntity> entities = new List<PreKeyEntity>();

            foreach (PreKeyRecord record in records)
            {
                PreKeyEntity entity = new PreKeyEntity(record.getId(),
                                                       record.getKeyPair().getPublicKey());

                entities.Add(entity);
            }

            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                   signedPreKey.getKeyPair().getPublicKey(),
                                                                   signedPreKey.getSignature());

            await MakeServiceRequestAsync(token, string.Format(PREKEY_PATH, ""), "PUT",
                JsonUtil.ToJson(new PreKeyState(entities, signedPreKeyEntity, identityKey)));
            return true;
        }

        public async Task<int> GetAvailablePreKeys(CancellationToken token)// throws IOException
        {
            string responseText = await MakeServiceRequestAsync(token, PREKEY_METADATA_PATH, "GET", null);
            PreKeyStatus preKeyStatus = JsonUtil.FromJson<PreKeyStatus>(responseText);

            return preKeyStatus.Count;
        }

        public async Task<List<PreKeyBundle>> GetPreKeys(CancellationToken token, SignalServiceAddress destination,
            UnidentifiedAccess? unidentifiedAccess, uint deviceIdInteger)// throws IOException
        {
            try
            {
                string deviceId = deviceIdInteger.ToString();

                if (deviceId.Equals("1"))
                    deviceId = "*";

                string path = string.Format(PREKEY_DEVICE_PATH, destination.E164number, deviceId);

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = await MakeServiceRequestAsync(token, path, "GET", null, unidentifiedAccess);
                PreKeyResponse response = JsonUtil.FromJson<PreKeyResponse>(responseText);
                List<PreKeyBundle> bundles = new List<PreKeyBundle>();

                foreach (PreKeyResponseItem device in response.Devices)
                {
                    ECPublicKey preKey = null;
                    ECPublicKey signedPreKey = null;
                    byte[] signedPreKeySignature = null;
                    int preKeyId = -1;
                    int signedPreKeyId = -1;

                    if (device.SignedPreKey != null)
                    {
                        signedPreKey = device.SignedPreKey.PublicKey;
                        signedPreKeyId = (int)device.SignedPreKey.KeyId;
                        signedPreKeySignature = device.SignedPreKey.Signature;
                    }

                    if (device.PreKey != null)
                    {
                        preKeyId = (int)device.PreKey.KeyId;
                        preKey = device.PreKey.PublicKey;
                    }

                    bundles.Add(new PreKeyBundle(device.RegistrationId, device.DeviceId, (uint)preKeyId,
                                                         preKey, (uint)signedPreKeyId, signedPreKey, signedPreKeySignature,
                                                         response.IdentityKey));
                }

                return bundles;
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.E164number, nfe);
            }
        }

        public async Task<PreKeyBundle> GetPreKey(CancellationToken token, SignalServiceAddress destination, uint deviceId)// throws IOException
        {
            try
            {
                string path = string.Format(PREKEY_DEVICE_PATH, destination.E164number,
                                            deviceId.ToString());

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = await MakeServiceRequestAsync(token, path, "GET", null);
                PreKeyResponse response = JsonUtil.FromJson<PreKeyResponse>(responseText);

                if (response.Devices == null || response.Devices.Count < 1)
                    throw new Exception("Empty prekey list");

                PreKeyResponseItem device = response.Devices[0];
                ECPublicKey? preKey = null;
                ECPublicKey? signedPreKey = null;
                byte[]? signedPreKeySignature = null;
                int preKeyId = -1;
                int signedPreKeyId = -1;

                if (device.PreKey != null)
                {
                    preKeyId = (int)device.PreKey.KeyId;
                    preKey = device.PreKey.PublicKey;
                }

                if (device.SignedPreKey != null)
                {
                    signedPreKeyId = (int)device.SignedPreKey.KeyId;
                    signedPreKey = device.SignedPreKey.PublicKey;
                    signedPreKeySignature = device.SignedPreKey.Signature;
                }

                return new PreKeyBundle(device.RegistrationId, device.DeviceId, (uint)preKeyId, preKey,
                                        (uint)signedPreKeyId, signedPreKey, signedPreKeySignature, response.IdentityKey);
            }
            /*catch (JsonUtil.JsonParseException e)
            {
                throw new IOException(e);
            }*/
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.E164number, nfe);
            }
        }

        public async Task<SignedPreKeyEntity> GetCurrentSignedPreKey(CancellationToken token)// throws IOException
        {
            try
            {
                string responseText = await MakeServiceRequestAsync(token, SIGNED_PREKEY_PATH, "GET", null);
                return JsonUtil.FromJson<SignedPreKeyEntity>(responseText);
            }
            catch (/*NotFound*/Exception e)
            {
                Logger.LogError("GetCurrentSignedPreKey() failed: {0}\n{1}", e.Message, e.StackTrace);
                return null;
            }
        }

        public async Task<bool> SetCurrentSignedPreKey(CancellationToken token, SignedPreKeyRecord signedPreKey)// throws IOException
        {
            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                           signedPreKey.getKeyPair().getPublicKey(),
                                                                           signedPreKey.getSignature());
            await MakeServiceRequestAsync(token, SIGNED_PREKEY_PATH, "PUT", JsonUtil.ToJson(signedPreKeyEntity));
            return true;
        }

        public async Task<(ulong id, byte[] digest)> SendAttachment(CancellationToken token, PushAttachmentData attachment)// throws IOException
        {
            var (id, location) = await RetrieveAttachmentUploadUrl(token);

            byte[] digest = await UploadAttachment(token, "PUT", location, attachment.Data,
                attachment.DataSize, attachment.OutputFactory, attachment.Listener);

            return (id, digest);
        }

        /// <summary>
        /// Gets a URL that can be used to upload an attachment
        /// </summary>
        /// <returns>The attachment ID and the URL</returns>
        public async Task<(ulong id, string location)> RetrieveAttachmentUploadUrl(CancellationToken token)
        {
            string response = await MakeServiceRequestAsync(token, string.Format(ATTACHMENT_PATH, ""), "GET", null);
            AttachmentDescriptor attachmentKey = JsonUtil.FromJson<AttachmentDescriptor>(response);

            if (attachmentKey == null || attachmentKey.Location == null)
            {
                throw new Exception("Server failed to allocate an attachment key!");
            }
            return (attachmentKey.Id, attachmentKey.Location);
        }

        public async Task RetrieveAttachment(CancellationToken token, ulong attachmentId, Stream tmpDestination, int maxSizeBytes)
        {
            string attachmentUrlLocation = await RetrieveAttachmentDownloadUrl(token, attachmentId);
            await DownloadAttachment(token, attachmentUrlLocation, tmpDestination);
        }

        /// <summary>
        /// Gets the URL location of an attachment
        /// </summary>
        public async Task<string> RetrieveAttachmentDownloadUrl(CancellationToken token, ulong attachmentId)
        {
            string path = string.Format(ATTACHMENT_PATH, attachmentId.ToString());

            string response = await MakeServiceRequestAsync(token, path, "GET", null);
            AttachmentDescriptor descriptor = JsonUtil.FromJson<AttachmentDescriptor>(response);
            return descriptor.Location;
        }

        public async Task<SignalServiceProfile> RetrieveProfile(CancellationToken token, SignalServiceAddress target, UnidentifiedAccess? unidentifiedAccess)
        {
            try
            {
                string response = await MakeServiceRequestAsync(token, string.Format(PROFILE_PATH, target.E164number), "GET", null, unidentifiedAccess);
                return JsonUtil.FromJson<SignalServiceProfile>(response);
            }
            catch (Exception e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity: "+e.Message);
            }
        }

        public void RetrieveProfileAvatar(string path, FileStream destination, int maxSizeByzes)
        {
            DownloadFromCdn(destination, path, maxSizeByzes);
        }

        public async Task SetProfileName(CancellationToken token, string name)
        {
            await MakeServiceRequestAsync(token, string.Format(PROFILE_PATH, "name/" + (name == null ? "" : WebUtility.UrlEncode(name))), "PUT", "");
        }

        public async Task SetProfileAvatar(CancellationToken token, ProfileAvatarData profileAvatar)
        {
            String response = await MakeServiceRequestAsync(token, string.Format(PROFILE_PATH, "form/avatar"), "GET", null);
            ProfileAvatarUploadAttributes formAttributes;

            try
            {
                formAttributes = JsonUtil.FromJson<ProfileAvatarUploadAttributes>(response);
            }
            catch (IOException e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity ("+e.Message+")");
            }

            if (profileAvatar != null)
            {
                UploadToCdn(formAttributes.Acl, formAttributes.Key,
                    formAttributes.Policy, formAttributes.Algorithm,
                    formAttributes.Credential, formAttributes.Date,
                    formAttributes.Signature, profileAvatar.InputData,
                    profileAvatar.ContentType, profileAvatar.DataLength,
                    profileAvatar.OutputStreamFactory);
            }
        }

        private void DownloadFromCdn(Stream destination, string path, int maxSizeBytes)
        {
            SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalCdnUrls);
            string url = signalUrl.Url;
            string hostHeader = signalUrl.HostHeader;
            throw new NotImplementedException(); //TODO
        }

        private void UploadToCdn(string acl, string key, string policy, string algorithm, string credential, string date,
            string signature, Stream inputData, string contentType, long dataLength, IOutputStreamFactory outputStreamFactory)
        {
            SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalCdnUrls);
            string url = signalUrl.Url;
            string hostHeader = signalUrl.HostHeader;
            throw new NotImplementedException(); //TODO
        }

        public async Task<List<ContactTokenDetails>> RetrieveDirectory(CancellationToken token, ICollection<string> contactTokens) // TODO: whacky
                                                                                                                                   //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            LinkedList<HashSet<string>> temp = new LinkedList<HashSet<string>>();
            ContactTokenList contactTokenList = new ContactTokenList(contactTokens.ToList());
            string response = await MakeServiceRequestAsync(token, DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.ToJson(contactTokenList));
            ContactTokenDetailsList activeTokens = JsonUtil.FromJson<ContactTokenDetailsList>(response);

            return activeTokens.Contacts;
        }

        public async Task<ContactTokenDetails?> GetContactTokenDetails(CancellationToken token, string contactToken)// throws IOException
        {
            try
            {
                string response = await MakeServiceRequestAsync(token, string.Format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null);
                return JsonUtil.FromJson<ContactTokenDetails>(response);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<string> GetContactDiscoveryAuthorization(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            string response = await MakeServiceRequestAsync(token.Value, DIRECTORY_AUTH_PATH, "GET", null);
            ContactDiscoveryCredentials credentials = JsonUtil.FromJson<ContactDiscoveryCredentials>(response);
            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.Username}:{credentials.Password}"))).ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="authorization"></param>
        /// <param name="request"></param>
        /// <param name="mrenclave"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<(RemoteAttestationResponse, IList<string>)> GetContactDiscoveryRemoteAttestation(string authorization, RemoteAttestationRequest request, string mrenclave, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            HttpResponseMessage response = await MakeContactDiscoveryRequestAsync(authorization, new List<string>(), $"/v1/attestation/{mrenclave}", "PUT", JsonUtil.ToJson(request), token);
            HttpContent body = response.Content;
            IEnumerable<string> rawCookies = response.Headers.GetValues("Set-Cookie");
            List<string> cookies = new List<string>();

            foreach (string cookie in rawCookies)
            {
                cookies.Add(cookie.Split(';')[0]);
            }

            if (body != null)
            {
                return (JsonUtil.FromJson<RemoteAttestationResponse>(await body.ReadAsStringAsync()), cookies);
            }
            else
            {
                throw new NonSuccessfulResponseCodeException("Empty response!");
            }
        }

        public async Task ReportContactDiscoveryServiceMatch(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/ok", "PUT", "");
        }

        public async Task ReportContactDiscoveryServiceMismatch(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/mismatch", "PUT", "");
        }

        public async Task ReportContactDiscoveryServiceServerError(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/server-error", "PUT", "");
        }

        public async Task ReportContactDiscoveryServiceClientError(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/client-error", "PUT", "");
        }

        public async Task ReportContactDiscoveryServiceAttestationError(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/attestation-error", "PUT", "");
        }

        public async Task ReportContactDiscoveryServiceUnexpectedError(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            await MakeServiceRequestAsync(token.Value, "/v1/directory/feedback/unexpected-error", "PUT", "");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="authorizationToken"></param>
        /// <param name="request"></param>
        /// <param name="cookies"></param>
        /// <param name="mrenclave"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<DiscoveryResponse> GetContactDiscoveryRegisteredUsers(string authorizationToken, DiscoveryRequest request, IList<string> cookies, string mrenclave, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            HttpContent body = (await MakeContactDiscoveryRequestAsync(authorizationToken, new List<string>(), $"/v1/discovery/{mrenclave}", "PUT", JsonUtil.ToJson(request), token)).Content;

            if (body != null)
            {
                return JsonUtil.FromJson<DiscoveryResponse>(await body.ReadAsStringAsync());
            }
            else
            {
                throw new NonSuccessfulResponseCodeException("Empty response!");
            }
        }

        public async Task<TurnServerInfo> GetTurnServerInfo(CancellationToken token)
        {
            string response = await MakeServiceRequestAsync(token, TURN_SERVER_INFO, "GET", null);
            return JsonUtil.FromJson<TurnServerInfo>(response);
        }

        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            throw new NotImplementedException();
        }

        public void CancelInFlightRequests()
        {
            throw new NotImplementedException();
        }

        private async Task DownloadAttachment(CancellationToken token, string url, Stream localDestination)
        {
            try
            {
                HttpClient connection = Util.CreateHttpClient();
                var headers = connection.DefaultRequestHeaders;
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Content = new StringContent("");
                req.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
                using (var resp = await connection.SendAsync(req, token))
                {
                    Stream input = await resp.Content.ReadAsStreamAsync();
                    byte[] buffer = new byte[32768];
                    int read = 0;
                    while (true)
                    {
                        read = input.Read(buffer, 0, 32768);
                        if (read == 0)
                        {
                            localDestination.Flush();
                            return;
                        }
                        localDestination.Write(buffer, 0, read);
                    }
                }
            }
            catch (Exception ioe)
            {
                Logger.LogError("DownloadAttachment() failed: {0}\n{1}", ioe.Message, ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }
        }

        private async Task<byte[]> UploadAttachment(CancellationToken token, string method, string url, Stream data, long dataSize,
            IOutputStreamFactory outputStreamFactory, IProgressListener listener)
        {
            // buffer payload in memory...
            MemoryStream tmpStream = new MemoryStream();
            DigestingOutputStream outputStream = outputStreamFactory.CreateFor(tmpStream);
            StreamContent streamContent = new StreamContent(tmpStream);
            data.CopyTo(outputStream);
            outputStream.Flush();
            tmpStream.Position = 0;

            // ... and upload it!
            var request = new HttpRequestMessage(HttpMethod.Put, url)
            {
                Content = new StreamContent(tmpStream)
            };
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Headers.ConnectionClose = true;
            HttpClient client = Util.CreateHttpClient();
            HttpResponseMessage response = await client.SendAsync(request, token);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new IOException($"Bad response: {response.StatusCode} {await response.Content.ReadAsStringAsync()}");
            }

            return outputStream.GetTransmittedDigest();
        }

        /// <summary>
        /// Encrypts an attachment to be uploaded
        /// </summary>
        /// <param name="data">The data stream of the attachment</param>
        /// <param name="key">64 random bytes</param>
        /// <returns>The digest and the encrypted data</returns>
        public (byte[] digest, Stream encryptedData) EncryptAttachment(Stream data, byte[] key)
        {
            // This stream will hold the encrypted data
            MemoryStream memoryStream = new MemoryStream();

            // This is the final digest
            byte[] digest = new byte[0];

            byte[][] keyParts = Util.Split(key, 32, 32);
            using (var mac = new HMACSHA256())
            {
                using (var cipher = Aes.Create())
                {
                    cipher.Key = keyParts[0];
                    cipher.Mode = CipherMode.CBC;
                    cipher.Padding = PaddingMode.PKCS7;
                    mac.Key = keyParts[1];

                    // First write the IV to the memory stream
                    memoryStream.Write(cipher.IV, 0, cipher.IV.Length);
                    using (var encrypt = cipher.CreateEncryptor())
                    using (var cryptoStream = new CryptoStream(memoryStream, encrypt, CryptoStreamMode.Write))
                    {
                        // Then read from the data stream and write it to the crypto stream
                        byte[] buffer = new byte[32768];
                        int read = data.Read(buffer, 0, buffer.Length);
                        while (read > 0)
                        {
                            cryptoStream.Write(buffer, 0, read);
                            read = data.Read(buffer, 0, buffer.Length);
                        }
                        cryptoStream.Flush();
                        cryptoStream.FlushFinalBlock();

                        // Then hash the stream and write the hash to the end
                        memoryStream.Seek(0, SeekOrigin.Begin);
                        byte[] auth = mac.ComputeHash(memoryStream);
                        memoryStream.Write(auth, 0, auth.Length);

                        // Then get the digest of the entire file
                        using (SHA256 sha = SHA256.Create())
                        {
                            memoryStream.Seek(0, SeekOrigin.Begin);
                            digest = sha.ComputeHash(memoryStream);
                        }
                    }
                }
            }

            // The crypto stream closed the stream so we need to make a new one
            MemoryStream encryptedData = new MemoryStream(memoryStream.ToArray());
            return (digest, encryptedData);
        }

        private async Task<string> MakeServiceRequestAsync(CancellationToken token, string urlFragment, string method, string? body)
        {
            return await MakeServiceRequestAsync(token, urlFragment, method, body, null);
        }


        private async Task<string> MakeServiceRequestAsync(CancellationToken token, string urlFragment, string method, string? body, UnidentifiedAccess? unidentifiedAccess)
        //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            HttpResponseMessage connection = await GetServiceConnectionAsync(token, urlFragment, method, body, unidentifiedAccess);
            HttpStatusCode responseCode;
            string responseMessage;
            string responseBody;

            try
            {
                responseCode = connection.StatusCode;
                responseMessage = connection.ReasonPhrase;
                responseBody = await connection.Content.ReadAsStringAsync();
            }
            catch (Exception ioe)
            {
                Logger.LogError("MakeServiceRequestAsync failed: {0}\n{1}", ioe.Message, ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }

            switch ((uint)responseCode)
            {
                case 413: // HttpStatusCode.RequestEntityTooLarge
                    throw new RateLimitException("Rate limit exceeded: " + responseCode);
                case 401: // HttpStatusCode.Unauthorized
                case 403: // HttpStatusCode.Forbidden
                    throw new AuthorizationFailedException("Authorization failed!");
                case 404: // HttpStatusCode.NotFound
                    throw new NotFoundException("Not found");
                case 409: // HttpStatusCode.Conflict
                    MismatchedDevices mismatchedDevices = null;
                    try
                    {
                        mismatchedDevices = JsonUtil.FromJson<MismatchedDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Logger.LogError("MakeServiceRequestAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new MismatchedDevicesException(mismatchedDevices);
                case 410: // HttpStatusCode.Gone
                    StaleDevices staleDevices = null;
                    try
                    {
                        staleDevices = JsonUtil.FromJson<StaleDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Logger.LogError("MakeServiceRequestAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new StaleDevicesException(staleDevices);
                case 411: //HttpStatusCode.LengthRequired
                    DeviceLimit deviceLimit = null;
                    try
                    {
                        deviceLimit = JsonUtil.FromJson<DeviceLimit>(responseBody);
                    }
                    catch (Exception e)
                    {
                        throw new PushNetworkException(e);
                    }
                    throw new DeviceLimitExceededException(deviceLimit);
                case 417: // HttpStatusCode.ExpectationFailed
                    throw new ExpectationFailedException();
                case 423:
                    RegistrationLockFailure accountLockFailure;
                    try
                    {
                        accountLockFailure = JsonUtil.FromJson<RegistrationLockFailure>(responseBody);
                    }
                    catch (Exception e)
                    {
                        throw new PushNetworkException(e);
                    }
                    throw new LockedException(accountLockFailure.Length, accountLockFailure.TimeRemaining);
            }

            if (responseCode != HttpStatusCode.OK && responseCode != HttpStatusCode.NoContent) // 200 & 204
            {
                throw new NonSuccessfulResponseCodeException("Bad response: " + (int)responseCode + " " +
                                                             responseMessage);
            }

            return responseBody;
        }

        private async Task<HttpResponseMessage> GetServiceConnectionAsync(CancellationToken token, string urlFragment, string method, string? body, UnidentifiedAccess? unidentifiedAccess)
        {
            try
            {
                SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalServiceUrls);
                string url = signalUrl.Url;
                string? hostHeader = signalUrl.HostHeader;
                Uri uri = new Uri(string.Format("{0}{1}", url, urlFragment));
                using HttpClient connection = Util.CreateHttpClient();

                var headers = connection.DefaultRequestHeaders;

                if (unidentifiedAccess != null)
                {
                    headers.Add("Unidentified-Access-Key", Base64.EncodeBytes(unidentifiedAccess.UnidentifiedAccessKey));
                }
                if (CredentialsProvider.Password != null)
                {
                    string authHeader = GetAuthorizationHeader(CredentialsProvider);
                    headers.Add("Authorization", authHeader);
                }

                if (UserAgent != null)
                {
                    headers.Add("X-Signal-Agent", UserAgent);
                }

                if (hostHeader != null)
                {
                    headers.Host = hostHeader;
                }

                StringContent content;
                if (body != null)
                {
                    content = new StringContent(body, Encoding.UTF8, "application/json");
                }
                else
                {
                    content = new StringContent("");
                }
                switch (method)
                {
                    case "POST":
                        return await connection.PostAsync(uri, content, token);

                    case "PUT":
                        return await connection.PutAsync(uri, content, token);

                    case "DELETE":
                        return await connection.DeleteAsync(uri, token);

                    case "GET":
                        return await connection.GetAsync(uri, token);

                    default:
                        throw new Exception("Unknown method: " + method);
                }
            }
            catch (Exception e)
            {
                Logger.LogError("GetServiceConnectionAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                throw new PushNetworkException(e);
            }
        }

        private async Task<HttpResponseMessage> MakeContactDiscoveryRequestAsync(string authorization, IList<string> cookies, string path, string method, string body, CancellationToken? token)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }
            SignalContactDiscoveryUrl signalContactDiscoveryUrl = GetRandom(SignalConnectionInformation.SignalContactDiscoveryUrls);
            string url = signalContactDiscoveryUrl.Url;
            string? hostHeader = signalContactDiscoveryUrl.HostHeader;
            Uri uri = new Uri($"{url}{path}");
            using HttpClient connection = Util.CreateHttpClient();

            StringContent content;
            if (body != null)
            {
                content = new StringContent(body, Encoding.UTF8, "application/json");
            }
            else
            {
                content = new StringContent("");
            }

            var headers = connection.DefaultRequestHeaders;

            if (hostHeader != null)
            {
                headers.Host = hostHeader;
            }

            if (authorization != null)
            {
                headers.Add("Authorization", authorization);
            }

            if (cookies != null && cookies.Count > 0)
            {
                headers.Add("Cookie", string.Join("; ", cookies));
            }

            HttpResponseMessage response;

            try
            {
                switch (method)
                {
                    case "POST":
                        response = await connection.PostAsync(uri, content, token.Value);
                        break;
                    case "PUT":
                        response = await connection.PutAsync(uri, content, token.Value);
                        break;
                    case "DELETE":
                        response = await connection.DeleteAsync(uri, token.Value);
                        break;
                    case "GET":
                        response = await connection.GetAsync(uri, token.Value);
                        break;
                    default:
                        throw new Exception($"Unknown method: {method}");
                }

                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
            }
            catch (Exception ex)
            {
                throw new PushNetworkException(ex);
            }

            throw new NonSuccessfulResponseCodeException($"Response: {response}");
        }

        private string GetAuthorizationHeader(ICredentialsProvider provider)
        {
            if (provider.DeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((provider.User + ":" + provider.Password)));
            }
            else
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((provider.User + "." + provider.DeviceId + ":" + provider.Password)));
            }
        }

        private T GetRandom<T>(T[] connections)
        {
            return connections[Util.generateRandomNumber() % connections.Length];
        }
    }

    internal class GcmRegistrationId
    {
        [JsonProperty("wnsRegistrationId")]
        public string WnsRegistrationId { get; }

        [JsonProperty("webSocketChannel")]
        public bool WebSocketChannel { get; }

        public GcmRegistrationId(string wnsRegistrationId, bool webSocketChannel)
        {
            WnsRegistrationId = wnsRegistrationId;
            WebSocketChannel = webSocketChannel;
        }
    }

    internal class RegistrationLock
    {
        [JsonProperty("pin")]
        public string Pin { get; }

        public RegistrationLock(string pin)
        {
            Pin = pin;
        }
    }

    internal class RegistrationLockFailure
    {
        [JsonProperty("length")]
        public int Length { get; private set; }
        [JsonProperty("timeRemaining")]
        public long TimeRemaining { get; private set; }

        public RegistrationLockFailure() { }
    }

    internal class AttachmentDescriptor
    {
        [JsonProperty("id")]
        public ulong Id { get; set; }

        [JsonProperty("location")]
        public string Location { get; set; }

        public AttachmentDescriptor() { }
    }
}
