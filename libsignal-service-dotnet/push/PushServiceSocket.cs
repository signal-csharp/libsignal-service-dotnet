using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignaldotnet.push.http;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.profiles;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Newtonsoft.Json;
using Strilanc.Value;

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
using System.Threading.Tasks;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    internal class PushServiceSocket
    {
        private static readonly string TAG = "PushServiceSocket";
        private static readonly string CREATE_ACCOUNT_SMS_PATH = "/v1/accounts/sms/code/{0}";
        private static readonly string CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/{0}";
        private static readonly string VERIFY_ACCOUNT_CODE_PATH = "/v1/accounts/code/{0}";
        private static readonly string VERIFY_ACCOUNT_TOKEN_PATH = "/v1/accounts/token/{0}";
        private static readonly string REGISTER_GCM_PATH = "/v1/accounts/gcm/";
        private static readonly string REQUEST_TOKEN_PATH = "/v1/accounts/token";
        private static readonly string TURN_SERVER_INFO = "/v1/accounts/turn";
        private static readonly string SET_ACCOUNT_ATTRIBUTES = "/v1/accounts/attributes";

        private static readonly string PREKEY_METADATA_PATH = "/v2/keys/";
        private static readonly string PREKEY_PATH = "/v2/keys/{0}";
        private static readonly string PREKEY_DEVICE_PATH = "/v2/keys/{0}/{1}";
        private static readonly string SIGNED_PREKEY_PATH = "/v2/keys/signed";

        private static readonly string PROVISIONING_CODE_PATH = "/v1/devices/provisioning/code";
        private static readonly string PROVISIONING_MESSAGE_PATH = "/v1/provisioning/{0}";
        private static readonly string DEVICE_PATH = "/v1/devices/{0}";

        private static readonly string DIRECTORY_TOKENS_PATH = "/v1/directory/tokens";
        private static readonly string DIRECTORY_VERIFY_PATH = "/v1/directory/{0}";
        private static readonly string MESSAGE_PATH = "/v1/messages/{0}";
        private static readonly string ACKNOWLEDGE_MESSAGE_PATH = "/v1/messages/{0}/{1}";
        private static readonly string RECEIPT_PATH = "/v1/receipt/{0}/{1}";
        private static readonly string ATTACHMENT_PATH = "/v1/attachments/{0}";

        private static readonly string PROFILE_PATH = "/v1/profile/%s";

        private readonly SignalServiceConfiguration SignalConnectionInformation;
        private readonly CredentialsProvider CredentialsProvider;
        private readonly string UserAgent;

        public PushServiceSocket(SignalServiceConfiguration serviceUrls, CredentialsProvider credentialsProvider, string userAgent)
        {
            CredentialsProvider = credentialsProvider;
            UserAgent = userAgent;
            SignalConnectionInformation = serviceUrls;
        }

        public bool CreateAccount(bool voice)
        {
            string path = voice ? CREATE_ACCOUNT_VOICE_PATH : CREATE_ACCOUNT_SMS_PATH;
            MakeServiceRequest(string.Format(path, CredentialsProvider.GetUser()), "GET", null);
            return true;
        }

        public bool VerifyAccountCode(string verificationCode, string signalingKey, uint registrationId, bool fetchesMessages)
        {
            AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages);
            MakeServiceRequest(string.Format(VERIFY_ACCOUNT_CODE_PATH, verificationCode), "PUT", JsonUtil.toJson(signalingKeyEntity));
            return true;
        }

        public bool SetAccountAttributes(string signalingKey, uint registrationId, bool fetchesMessages)
        {
            AccountAttributes accountAttributesEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages);
            MakeServiceRequest(SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.toJson(accountAttributesEntity));
            return true;
        }

        public string getAccountVerificationToken()// throws IOException
        {
            string responseText = MakeServiceRequest(REQUEST_TOKEN_PATH, "GET", null);
            return JsonUtil.fromJson<AuthorizationToken>(responseText).Token;
        }

        public int finishNewDeviceRegistration(String code, String signalingKey, bool supportsSms, bool fetchesMessages, int registrationId, String deviceName)
        {
            ConfirmCodeMessage javaJson = new ConfirmCodeMessage(signalingKey, supportsSms, fetchesMessages, registrationId, deviceName);
            string json = JsonUtil.toJson(javaJson);
            string responseText = MakeServiceRequest(string.Format(DEVICE_PATH, code), "PUT", json);
            DeviceId response = JsonUtil.fromJson<DeviceId>(responseText);
            return response.deviceId;
        }

        public string getNewDeviceVerificationCode()// throws IOException
        {
            string responseText = MakeServiceRequest(PROVISIONING_CODE_PATH, "GET", null);
            return JsonUtil.fromJson<DeviceCode>(responseText).getVerificationCode();
        }

        public bool sendProvisioningMessage(string destination, byte[] body)// throws IOException
        {
            MakeServiceRequest(string.Format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                    JsonUtil.toJson(new ProvisioningMessage(Base64.encodeBytes(body))));
            return true;
        }

        public List<DeviceInfo> getDevices()// throws IOException
        {
            string responseText = MakeServiceRequest(string.Format(DEVICE_PATH, ""), "GET", null);
            return JsonUtil.fromJson<DeviceInfoList>(responseText).getDevices();
        }

        public bool removeDevice(long deviceId)// throws IOException
        {
            MakeServiceRequest(string.Format(DEVICE_PATH, deviceId), "DELETE", null);
            return true;
        }

        public bool sendReceipt(string destination, ulong messageId, May<string> relay)// throws IOException
        {
            string path = string.Format(RECEIPT_PATH, destination, messageId);

            if (relay.HasValue)
            {
                path += "?relay=" + relay.ForceGetValue();
            }

            MakeServiceRequest(path, "PUT", null);
            return true;
        }

        public void registerGcmId(String gcmRegistrationId)
        {
            GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
            MakeServiceRequest(REGISTER_GCM_PATH, "PUT", JsonUtil.toJson(registration));
        }

        public void unregisterGcmId()
        {
            MakeServiceRequest(REGISTER_GCM_PATH, "DELETE", null);
        }

        public SendMessageResponse sendMessage(OutgoingPushMessageList bundle)
        {
            try
            {
                string responseText = MakeServiceRequest(string.Format(MESSAGE_PATH, bundle.getDestination()), "PUT", JsonUtil.toJson(bundle));
                return JsonUtil.fromJson<SendMessageResponse>(responseText);
            }
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(bundle.getDestination(), nfe);
            }
        }

        public List<SignalServiceEnvelopeEntity> getMessages()// throws IOException
        {
            string responseText = MakeServiceRequest(string.Format(MESSAGE_PATH, ""), "GET", null);
            return JsonUtil.fromJson<SignalServiceEnvelopeEntityList>(responseText).getMessages();
        }

        public bool acknowledgeMessage(string sender, ulong timestamp)// throws IOException
        {
            MakeServiceRequest(string.Format(ACKNOWLEDGE_MESSAGE_PATH, sender, timestamp), "DELETE", null);
            return true;
        }

        public bool registerPreKeys(IdentityKey identityKey,
                                    SignedPreKeyRecord signedPreKey,
                                    IList<PreKeyRecord> records)
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

            MakeServiceRequest(string.Format(PREKEY_PATH, ""), "PUT",
                JsonUtil.toJson(new PreKeyState(entities, signedPreKeyEntity, identityKey)));
            return true;
        }

        public int getAvailablePreKeys()// throws IOException
        {
            string responseText = MakeServiceRequest(PREKEY_METADATA_PATH, "GET", null);
            PreKeyStatus preKeyStatus = JsonUtil.fromJson<PreKeyStatus>(responseText);

            return preKeyStatus.getCount();
        }

        public List<PreKeyBundle> getPreKeys(SignalServiceAddress destination, uint deviceIdInteger)// throws IOException
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

                string responseText = MakeServiceRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.fromJson<PreKeyResponse>(responseText);
                List<PreKeyBundle> bundles = new List<PreKeyBundle>();

                foreach (PreKeyResponseItem device in response.getDevices())
                {
                    ECPublicKey preKey = null;
                    ECPublicKey signedPreKey = null;
                    byte[] signedPreKeySignature = null;
                    int preKeyId = -1;
                    int signedPreKeyId = -1;

                    if (device.getSignedPreKey() != null)
                    {
                        signedPreKey = device.getSignedPreKey().getPublicKey();
                        signedPreKeyId = (int)device.getSignedPreKey().getKeyId(); // TODO: whacky
                        signedPreKeySignature = device.getSignedPreKey().getSignature();
                    }

                    if (device.getPreKey() != null)
                    {
                        preKeyId = (int)device.getPreKey().getKeyId();// TODO: whacky
                        preKey = device.getPreKey().getPublicKey();
                    }

                    bundles.Add(new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), (uint)preKeyId,
                                                         preKey, (uint)signedPreKeyId, signedPreKey, signedPreKeySignature,
                                                         response.getIdentityKey()));// TODO: whacky
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

        public PreKeyBundle getPreKey(SignalServiceAddress destination, uint deviceId)// throws IOException
        {
            try
            {
                string path = string.Format(PREKEY_DEVICE_PATH, destination.E164number,
                                            deviceId.ToString());

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = MakeServiceRequest(path, "GET", null);
                PreKeyResponse response = JsonUtil.fromJson<PreKeyResponse>(responseText);

                if (response.getDevices() == null || response.getDevices().Count < 1)
                    throw new Exception("Empty prekey list");

                PreKeyResponseItem device = response.getDevices()[0];
                ECPublicKey preKey = null;
                ECPublicKey signedPreKey = null;
                byte[] signedPreKeySignature = null;
                int preKeyId = -1;
                int signedPreKeyId = -1;

                if (device.getPreKey() != null)
                {
                    preKeyId = (int)device.getPreKey().getKeyId();// TODO: whacky
                    preKey = device.getPreKey().getPublicKey();
                }

                if (device.getSignedPreKey() != null)
                {
                    signedPreKeyId = (int)device.getSignedPreKey().getKeyId();// TODO: whacky
                    signedPreKey = device.getSignedPreKey().getPublicKey();
                    signedPreKeySignature = device.getSignedPreKey().getSignature();
                }

                return new PreKeyBundle(device.getRegistrationId(), device.getDeviceId(), (uint)preKeyId, preKey,
                                        (uint)signedPreKeyId, signedPreKey, signedPreKeySignature, response.getIdentityKey());
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

        public SignedPreKeyEntity getCurrentSignedPreKey()// throws IOException
        {
            try
            {
                string responseText = MakeServiceRequest(SIGNED_PREKEY_PATH, "GET", null);
                return JsonUtil.fromJson<SignedPreKeyEntity>(responseText);
            }
            catch (/*NotFound*/Exception e)
            {
                Debug.WriteLine(e.Message, TAG);
                return null;
            }
        }

        public bool setCurrentSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                           signedPreKey.getKeyPair().getPublicKey(),
                                                                           signedPreKey.getSignature());
            MakeServiceRequest(SIGNED_PREKEY_PATH, "PUT", JsonUtil.toJson(signedPreKeyEntity));
            return true;
        }

        public (ulong id, byte[] digest) SendAttachment(PushAttachmentData attachment)// throws IOException
        {
            var attachmentInfo = RetrieveAttachmentUploadUrl();

            byte[] digest = UploadAttachment("PUT", attachmentInfo.location, attachment.Data,
                attachment.DataSize, attachment.OutputFactory, attachment.Listener);

            return (attachmentInfo.id, digest);
        }

        /// <summary>
        /// Gets a URL that can be used to upload an attachment
        /// </summary>
        /// <returns>The attachment ID and the URL</returns>
        public (ulong id, string location) RetrieveAttachmentUploadUrl()
        {
            string response = MakeServiceRequest(string.Format(ATTACHMENT_PATH, ""), "GET", null);
            AttachmentDescriptor attachmentKey = JsonUtil.fromJson<AttachmentDescriptor>(response);

            if (attachmentKey == null || attachmentKey.getLocation() == null)
            {
                throw new Exception("Server failed to allocate an attachment key!");
            }

            Debug.WriteLine("Got attachment content location: " + attachmentKey.getLocation(), TAG);
            return (attachmentKey.getId(), attachmentKey.getLocation());
        }

        public void RetrieveAttachment(string relay, ulong attachmentId, Stream tmpDestination, int maxSizeBytes)
        {
            string attachmentUrlLocation = RetrieveAttachmentDownloadUrl(relay, attachmentId);
            DownloadAttachment(attachmentUrlLocation, tmpDestination);
        }

        /// <summary>
        /// Gets the URL location of an attachment
        /// </summary>
        /// <param name="relay"></param>
        /// <param name="attachmentId"></param>
        /// <returns></returns>
        public string RetrieveAttachmentDownloadUrl(string relay, ulong attachmentId)
        {
            string path = string.Format(ATTACHMENT_PATH, attachmentId.ToString());

            if (!Util.isEmpty(relay))
            {
                path = path + "?relay=" + relay;
            }

            string response = MakeServiceRequest(path, "GET", null);
            Debug.WriteLine("PushServiceSocket: Received resp " + response);
            AttachmentDescriptor descriptor = JsonUtil.fromJson<AttachmentDescriptor>(response);
            Debug.WriteLine("PushServiceSocket: Attachment: " + attachmentId + " is at: " + descriptor.getLocation());
            return descriptor.getLocation();
        }

        public SignalServiceProfile RetrieveProfile(SignalServiceAddress target)
        {
            try
            {
                string response = MakeServiceRequest(string.Format(PROFILE_PATH, target.E164number), "GET", null);
                return JsonUtil.fromJson<SignalServiceProfile>(response);
            }
            catch (Exception e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity: "+e.Message);
            }
        }

        public void SetProfileName(string name)
        {
            MakeServiceRequest(string.Format(PROFILE_PATH, "name/" + (name == null ? "" : WebUtility.UrlEncode(name))), "PUT", "");
        }

        public void SetProfileAvatar(ProfileAvatarData profileAvatar)
        {
            String response = MakeServiceRequest(string.Format(PROFILE_PATH, "form/avatar"), "GET", null);
            ProfileAvatarUploadAttributes formAttributes;

            try
            {
                formAttributes = JsonUtil.fromJson< ProfileAvatarUploadAttributes>(response);
            }
            catch (IOException e)
            {
                throw new NonSuccessfulResponseCodeException("Unable to parse entity");
            }

            if (profileAvatar != null) {
                UploadToCdn(formAttributes.acl, formAttributes.key,
                    formAttributes.policy, formAttributes.algorithm,
                    formAttributes.credential, formAttributes.date,
                    formAttributes.signature, profileAvatar.InputData,
                    profileAvatar.ContentType, profileAvatar.DataLength,
                    profileAvatar.OutputStreamFactory);
            }
        }

        private void UploadToCdn(string acl, string key, string policy, string algorithm, string credential, string date,
            string signature, Stream inputData, string contentType, long dataLength, OutputStreamFactory outputStreamFactory)
        {
            SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalCdnUrls);
            string url = signalUrl.Url;
            string hostHeader = signalUrl.HostHeader;
            throw new NotImplementedException(); //TODO
        }

        public List<ContactTokenDetails> retrieveDirectory(ICollection<string> contactTokens) // TODO: whacky
                                                                                              //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            LinkedList<HashSet<string>> temp = new LinkedList<HashSet<string>>();
            ContactTokenList contactTokenList = new ContactTokenList(contactTokens.ToList());
            string response = MakeServiceRequest(DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.toJson(contactTokenList));
            ContactTokenDetailsList activeTokens = JsonUtil.fromJson<ContactTokenDetailsList>(response);

            return activeTokens.getContacts();
        }

        public ContactTokenDetails getContactTokenDetails(string contactToken)// throws IOException
        {
            try
            {
                string response = MakeServiceRequest(string.Format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null);
                return JsonUtil.fromJson<ContactTokenDetails>(response);
            }
            catch (/*NotFound*/Exception nfe)
            {
                return null;
            }
        }

        public TurnServerInfo getTurnServerInfo()
        {
            throw new NotImplementedException();
        }

        public void setSoTimeoutMillis(long soTimeoutMillis)
        {
            throw new NotImplementedException();
        }

        public void cancelInFlightRequests()
        {
            throw new NotImplementedException();
        }

        private void DownloadAttachment(string url, Stream localDestination)
        {
            try
            {
                HttpClient connection = new HttpClient();
                var headers = connection.DefaultRequestHeaders;
                Debug.WriteLine("downloading " + url);
                HttpRequestMessage req = new HttpRequestMessage(HttpMethod.Get, url);
                req.Content = new StringContent("");
                req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/octet-stream");
                using (var resp = connection.SendAsync(req).Result)
                {
                    Stream input = resp.Content.ReadAsStreamAsync().Result;
                    byte[] buffer = new byte[4096];
                    int read = 0;
                    while (true)
                    {
                        read = input.Read(buffer, 0, 4096);
                        if (read == 0)
                        {
                            Debug.WriteLine("PushServiceSocket Downloaded: " + url + " to: " + localDestination);
                            return;
                        }
                        localDestination.Write(buffer, 0, read);
                    }
                }
            }
            catch (Exception ioe)
            {
                Debug.WriteLine(ioe.Message);
                Debug.WriteLine(ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }
        }

        private byte[] UploadAttachment(string method, string url, Stream data, ulong dataSize,
            OutputStreamFactory outputStreamFactory, ProgressListener listener)
        {
            MemoryStream tmpStream = new MemoryStream();
            DigestingOutputStream outputStream = outputStreamFactory.CreateFor(tmpStream);
            StreamContent streamContent = new StreamContent(tmpStream);
            var request = new HttpRequestMessage(HttpMethod.Put, url);
            request.Content = streamContent;
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
            request.Headers.ConnectionClose = true;

            HttpClient client = new HttpClient();
            HttpResponseMessage response = client.SendAsync(request).Result;
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new IOException($"Bad response: {response.StatusCode} {response.Content.ReadAsStringAsync().Result}");
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
                        byte[] buffer = new byte[4096];
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

        private string MakeServiceRequest(string urlFragment, string method, string body)
        //throws NonSuccessfulResponseCodeException, PushNetworkException
        {
            HttpResponseMessage connection = getServiceConnection(urlFragment, method, body);
            HttpStatusCode responseCode;
            string responseMessage;
            string responseBody;

            try
            {
                responseCode = connection.StatusCode;
                responseMessage = connection.ReasonPhrase;
                responseBody = connection.Content.ReadAsStringAsync().Result;
            }
            catch (Exception ioe)
            {
                Debug.WriteLine(ioe.Message);
                Debug.WriteLine(ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }

            switch (responseCode)
            {
                case HttpStatusCode.RequestEntityTooLarge: // 413
                    throw new RateLimitException("Rate limit exceeded: " + responseCode);
                case HttpStatusCode.Unauthorized: // 401
                case HttpStatusCode.Forbidden: // 403
                    throw new AuthorizationFailedException("Authorization failed!");
                case HttpStatusCode.NotFound: // 404
                    throw new NotFoundException("Not found");
                case HttpStatusCode.Conflict: // 409
                    MismatchedDevices mismatchedDevices = null;
                    try
                    {
                        mismatchedDevices = JsonUtil.fromJson<MismatchedDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new MismatchedDevicesException(mismatchedDevices);
                case HttpStatusCode.Gone: // 410
                    StaleDevices staleDevices = null;
                    try
                    {
                        staleDevices = JsonUtil.fromJson<StaleDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new StaleDevicesException(staleDevices);
                case HttpStatusCode.LengthRequired://411:
                    DeviceLimit deviceLimit = null;
                    try
                    {
                        deviceLimit = JsonUtil.fromJson<DeviceLimit>(responseBody);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine(e);
                        Debug.WriteLine(e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new DeviceLimitExceededException(deviceLimit);
                case HttpStatusCode.ExpectationFailed: // 417
                    throw new ExpectationFailedException();
            }

            if (responseCode != HttpStatusCode.OK && responseCode != HttpStatusCode.NoContent) // 200 & 204
            {
                throw new NonSuccessfulResponseCodeException("Bad response: " + (int)responseCode + " " +
                                                             responseMessage);
            }

            return responseBody;
        }

        private bool Func(HttpRequestMessage a, X509Certificate2 b, X509Chain c, SslPolicyErrors d)
        {
            return true;
        }

        private HttpResponseMessage getServiceConnection(string urlFragment, string method, string body)
        {
            try
            {
                SignalUrl signalUrl = GetRandom(SignalConnectionInformation.SignalServiceUrls);
                string url = signalUrl.Url;
                string hostHeader = signalUrl.HostHeader;
                Uri uri = new Uri(string.Format("{0}{1}", url, urlFragment));
                Debug.WriteLine("{0}: Uri {1}", TAG, uri);
                HttpClient connection = new HttpClient();

                var headers = connection.DefaultRequestHeaders;

                if (CredentialsProvider.GetPassword() != null)
                {
                    string authHeader = getAuthorizationHeader(CredentialsProvider);
                    Debug.WriteLine(String.Format("Authorization: {0}", authHeader), TAG);
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
                    Debug.WriteLine(body);
                }
                else
                {
                    content = new StringContent("");
                }
                switch (method)
                {
                    case "POST":
                        return connection.PostAsync(uri, content).Result;

                    case "PUT":
                        return connection.PutAsync(uri, content).Result;

                    case "DELETE":
                        return connection.DeleteAsync(uri).Result;

                    case "GET":
                        return connection.GetAsync(uri).Result;

                    default:
                        throw new Exception("Unknown method: " + method);
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine("getConnection() failed:", TAG);
                Debug.WriteLine(e.Message);
                Debug.WriteLine(e.StackTrace);
                throw new PushNetworkException(e);
            }
        }

        private string getAuthorizationHeader(CredentialsProvider provider)
        {
            if (provider.GetDeviceId() == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                return "Basic " + Base64.encodeBytes(Encoding.UTF8.GetBytes((provider.GetUser() + ":" + provider.GetPassword())));
            }
            else
            {
                return "Basic " + Base64.encodeBytes(Encoding.UTF8.GetBytes((provider.GetUser() + "." + provider.GetDeviceId() + ":" + provider.GetPassword())));
            }
        }

        private SignalUrl GetRandom(SignalUrl[] connections)
        {
            return connections[Util.generateRandomNumber() % connections.Length];
        }
    }

    internal class GcmRegistrationId
    {
        [JsonProperty]
        private string wnsRegistrationId;

        [JsonProperty]
        private bool webSocketChannel;

        public GcmRegistrationId()
        {
        }

        public GcmRegistrationId(string wnsRegistrationId, bool webSocketChannel)
        {
            this.wnsRegistrationId = wnsRegistrationId;
            this.webSocketChannel = webSocketChannel;
        }
    }

    internal class AttachmentDescriptor
    {
        [JsonProperty]
        private ulong id;

        [JsonProperty]
        private string location;

        public ulong getId()
        {
            return id;
        }

        public string getLocation()
        {
            return location;
        }
    }
}
