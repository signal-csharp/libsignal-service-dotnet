using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal_service_dotnet.messages.calls;
using libsignaldotnet.push.http;
using libsignalservice.configuration;
using libsignalservice.contacts.entities;
using libsignalservice.crypto;
using libsignalservice.messages;
using libsignalservice.messages.multidevice;
using libsignalservice.profiles;
using libsignalservice.push.exceptions;
using libsignalservice.push.http;
using libsignalservice.util;
using libsignalservicedotnet.crypto;
using libsignalservicedotnet.push;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using static libsignalservice.messages.SignalServiceAttachment;

namespace libsignalservice.push
{
    internal class PushServiceSocket
    {
        private const string CREATE_ACCOUNT_SMS_PATH = "/v1/accounts/sms/code/{0}";
        private const string CREATE_ACCOUNT_VOICE_PATH = "/v1/accounts/voice/code/{0}";
        private const string VERIFY_ACCOUNT_CODE_PATH = "/v1/accounts/code/{0}";
        private const string REGISTER_GCM_PATH = "/v1/accounts/gcm/";
        private const string TURN_SERVER_INFO = "/v1/accounts/turn";
        private const string SET_ACCOUNT_ATTRIBUTES = "/v1/accounts/attributes";
        private const string PIN_PATH = "/v1/accounts/pin/";
        private const string WHO_AM_I = "/v1/accounts/whoami";

        private const string PREKEY_METADATA_PATH = "/v2/keys/";
        private const string PREKEY_PATH = "/v2/keys/{0}";
        private const string PREKEY_DEVICE_PATH = "/v2/keys/{0}/{1}";
        private const string SIGNED_PREKEY_PATH = "/v2/keys/signed";

        private const string PROVISIONING_CODE_PATH = "/v1/devices/provisioning/code";
        private const string PROVISIONING_MESSAGE_PATH = "/v1/provisioning/{0}";
        private const string DEVICE_PATH = "/v1/devices/{0}";

        private const string DIRECTORY_TOKENS_PATH = "/v1/directory/tokens";
        private const string DIRECTORY_VERIFY_PATH = "/v1/directory/{0}";
        private const string DIRECTORY_AUTH_PATH = "/v1/directory/auth";
        private const string MESSAGE_PATH = "/v1/messages/{0}";
        private const string SENDER_ACK_MESSAGE_PATH = "/v1/messages/{0}/{1}";
        private const string UUID_ACK_MESSAGE_PATH     = "/v1/messages/uuid/{0}";
        private const string ATTACHMENT_V2_PATH = "/v2/attachments/form/upload";
        private const string ATTACHMENT_V3_PATH = "/v3/attachments/form/upload";

        private const string PROFILE_PATH = "/v1/profile/%s";

        private const string SENDER_CERTIFICATE_LEGACY_PATH = "/v1/certificate/delivery";
        private const string SENDER_CERTIFICATE_PATH = "/v1/certificate/delivery?includeUuid=true";

        private const string ATTACHMENT_KEY_DOWNLOAD_PATH = "attachments/{0}";
        private const string ATTACHMENT_ID_DOWNLOAD_PATH = "attachments/{0}";
        private const string ATTACHMENT_UPLOAD_PATH = "attachments/";

        private const string STICKER_MANIFEST_PATH = "stickers/{0}/manifest.proto";
        private const string STICKER_PATH = "stickers/{0}/full/{1}";

        private readonly Dictionary<string, string> NO_HEADERS = new Dictionary<string, string>();

        private readonly ILogger logger = LibsignalLogging.CreateLogger<PushServiceSocket>();
        private readonly SignalServiceConfiguration signalConnectionInformation;
        private readonly ConnectionHolder[] cdnClients;
        private readonly ConnectionHolder[] cdn2Clients;
        private readonly ConnectionHolder[] contactDiscoveryClients;
        private readonly ICredentialsProvider credentialsProvider;
        private readonly string userAgent;
        private readonly HttpClient httpClient;

        public enum ClientSet
        {
            ContactDiscovery,
            KeyBackup
        }

        public PushServiceSocket(SignalServiceConfiguration serviceUrls,
            ICredentialsProvider credentialsProvider,
            string userAgent,
            HttpClient httpClient)
        {
            this.credentialsProvider = credentialsProvider;
            this.userAgent = userAgent;
            signalConnectionInformation = serviceUrls;
            this.httpClient = httpClient;

            cdnClients = CreateConnectionHolders(signalConnectionInformation.SignalCdnUrls);
            cdn2Clients = CreateConnectionHolders(signalConnectionInformation.SignalCdn2Urls);
            contactDiscoveryClients = CreateConnectionHolders(signalConnectionInformation.SignalContactDiscoveryUrls);
        }

        public async Task RequestSmsVerificationCodeAsync(string? captchaToken, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string path = string.Format(CREATE_ACCOUNT_SMS_PATH, credentialsProvider.E164);

            if (captchaToken != null)
            {
                path += $"?captcha={captchaToken}";
            }

            await MakeServiceRequestAsync(path, "GET", null, NO_HEADERS, (responseCode) =>
            {
                if (responseCode == 402)
                {
                    throw new CaptchaRequiredException();
                }
            }, token);
        }

        public async Task RequestVoiceVerificationCodeAsync(string? captchaToken, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string path = string.Format(CREATE_ACCOUNT_VOICE_PATH, credentialsProvider.E164);

            if (captchaToken != null)
            {
                path += $"?captcha={captchaToken}";
            }

            await MakeServiceRequestAsync(path, "GET", null, NO_HEADERS, (responseCode) =>
            {
                if (responseCode == 402)
                {
                    throw new CaptchaRequiredException();
                }
            }, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<Guid> GetOwnUuidAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string body = await MakeServiceRequestAsync(WHO_AM_I, "GET", null, token);
            WhoAmIResponse response = JsonUtil.FromJson<WhoAmIResponse>(body);
            Guid? uuid = UuidUtil.Parse(response.Uuid);

            if (uuid.HasValue)
            {
                return uuid.Value;
            }
            else
            {
                throw new IOException("Invalid UUID!");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="verificationCode"></param>
        /// <param name="signalingKey"></param>
        /// <param name="registrationId"></param>
        /// <param name="fetchesMessages"></param>
        /// <param name="pin"></param>
        /// <param name="unidentifiedAccessKey"></param>
        /// <param name="unrestrictedUnidentifiedAccess"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<Guid> VerifyAccountCodeAsync(string verificationCode, string signalingKey, uint registrationId, bool fetchesMessages, string pin,
            byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            AccountAttributes signalingKeyEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin, unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
            string requestBody = JsonUtil.ToJson(signalingKeyEntity);
            string responseBody = await MakeServiceRequestAsync(string.Format(VERIFY_ACCOUNT_CODE_PATH, verificationCode), "PUT", requestBody, token);
            VerifyAccountResponse response = JsonUtil.FromJson<VerifyAccountResponse>(responseBody);
            Guid? uuid = UuidUtil.Parse(response.Uuid);

            if (uuid.HasValue)
            {
                return uuid.Value;
            }
            else
            {
                throw new IOException("Invalid UUID!");
            }
        }

        public async Task<bool> SetAccountAttributesAsync(string signalingKey, uint registrationId, bool fetchesMessages, string pin,
            byte[] unidentifiedAccessKey, bool unrestrictedUnidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            AccountAttributes accountAttributesEntity = new AccountAttributes(signalingKey, registrationId, fetchesMessages, pin, unidentifiedAccessKey, unrestrictedUnidentifiedAccess);
            await MakeServiceRequestAsync(SET_ACCOUNT_ATTRIBUTES, "PUT", JsonUtil.ToJson(accountAttributesEntity), token);
            return true;
        }

        public async Task<int> FinishNewDeviceRegistrationAsync(string code, string signalingKey, bool supportsSms, bool fetchesMessages, int registrationId, string deviceName, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConfirmCodeMessage javaJson = new ConfirmCodeMessage(signalingKey, supportsSms, fetchesMessages, registrationId, deviceName);
            string json = JsonUtil.ToJson(javaJson);
            string responseText = await MakeServiceRequestAsync(string.Format(DEVICE_PATH, code), "PUT", json, token);
            DeviceId response = JsonUtil.FromJson<DeviceId>(responseText);
            return response.NewDeviceId;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<string> GetNewDeviceVerificationCodeAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(PROVISIONING_CODE_PATH, "GET", null, token);
            return JsonUtil.FromJson<DeviceCode>(responseText).VerificationCode;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="body"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> SendProvisioningMessageAsync(string destination, byte[] body, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(string.Format(PROVISIONING_MESSAGE_PATH, destination), "PUT",
                    JsonUtil.ToJson(new ProvisioningMessage(Base64.EncodeBytes(body))), token);
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<List<DeviceInfo>> GetDevicesAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(string.Format(DEVICE_PATH, ""), "GET", null, token);
            return JsonUtil.FromJson<DeviceInfoList>(responseText).Devices;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="deviceId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> RemoveDeviceAsync(long deviceId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(string.Format(DEVICE_PATH, deviceId), "DELETE", null, token);
            return true;
        }

        public async Task RegisterGcmIdAsync(string gcmRegistrationId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            GcmRegistrationId registration = new GcmRegistrationId(gcmRegistrationId, true);
            await MakeServiceRequestAsync(REGISTER_GCM_PATH, "PUT", JsonUtil.ToJson(registration), token);
        }

        public async Task UnregisterGcmIdAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(REGISTER_GCM_PATH, "DELETE", null, token);
        }

        public async Task SetPinAsync(string pin, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            RegistrationLock accountLock = new RegistrationLock(pin);
            await MakeServiceRequestAsync(PIN_PATH, "PUT", JsonUtil.ToJson(accountLock), token);
        }

        public async Task RemovePinAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(PIN_PATH, "PUT", null, token);
        }

        public async Task<byte[]> GetSenderCertificateLegacyAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(SENDER_CERTIFICATE_LEGACY_PATH, "GET", null, token);
            return JsonUtil.FromJson<SenderCertificate>(responseText).GetUnidentifiedCertificate();
        }

        public async Task<byte[]> GetSenderCertificateAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(SENDER_CERTIFICATE_PATH, "GET", null, token);
            return JsonUtil.FromJson<SenderCertificate>(responseText).GetUnidentifiedCertificate();
        }

        public async Task<SendMessageResponse> SendMessageAsync(OutgoingPushMessageList bundle, UnidentifiedAccess? unidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string responseText = await MakeServiceRequestAsync(string.Format(MESSAGE_PATH, bundle.Destination), "PUT", JsonUtil.ToJson(bundle), NO_HEADERS, EmptyResponseCodeHandler, unidentifiedAccess, token);
                return JsonUtil.FromJson<SendMessageResponse>(responseText);
            }
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(bundle.Destination, nfe);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<List<SignalServiceEnvelopeEntity>> GetMessagesAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(string.Format(MESSAGE_PATH, ""), "GET", null, token);
            return JsonUtil.FromJson<SignalServiceEnvelopeEntityList>(responseText).Messages;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="timestamp"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task AcknowledgeMessageAsync(string sender, ulong timestamp, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(string.Format(new CultureInfo("en-US"), SENDER_ACK_MESSAGE_PATH, sender, timestamp), "DELETE", null, token);
        }

        public async Task AcknowledgeMessageAsync(string uuid, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(string.Format(new CultureInfo("en-US"), UUID_ACK_MESSAGE_PATH, uuid), "DELETE", null, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="identityKey"></param>
        /// <param name="signedPreKey"></param>
        /// <param name="records"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> RegisterPreKeysAsync(IdentityKey identityKey, SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> records, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

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

            await MakeServiceRequestAsync(string.Format(PREKEY_PATH, ""), "PUT",
                JsonUtil.ToJson(new PreKeyState(entities, signedPreKeyEntity, identityKey)), token);
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<int> GetAvailablePreKeysAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string responseText = await MakeServiceRequestAsync(PREKEY_METADATA_PATH, "GET", null, token);
            PreKeyStatus preKeyStatus = JsonUtil.FromJson<PreKeyStatus>(responseText);

            return preKeyStatus.Count;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="deviceIdInteger"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<List<PreKeyBundle>> GetPreKeysAsync(SignalServiceAddress destination,
            UnidentifiedAccess? unidentifiedAccess, uint deviceIdInteger, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string deviceId = deviceIdInteger.ToString();

                if (deviceId.Equals("1"))
                    deviceId = "*";

                string path = string.Format(PREKEY_DEVICE_PATH, destination.GetIdentifier(), deviceId);

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = await MakeServiceRequestAsync(path, "GET", null, NO_HEADERS, EmptyResponseCodeHandler, unidentifiedAccess, token.Value);
                PreKeyResponse response = JsonUtil.FromJson<PreKeyResponse>(responseText);
                List<PreKeyBundle> bundles = new List<PreKeyBundle>();

                foreach (PreKeyResponseItem device in response.Devices)
                {
                    ECPublicKey? preKey = null;
                    ECPublicKey? signedPreKey = null;
                    byte[]? signedPreKeySignature = null;
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
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.GetIdentifier(), nfe);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="deviceId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<PreKeyBundle> GetPreKeyAsync(SignalServiceAddress destination, uint deviceId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string path = string.Format(PREKEY_DEVICE_PATH, destination.GetIdentifier(),
                                            deviceId.ToString());

                if (destination.Relay != null)
                {
                    path = path + "?relay=" + destination.Relay;
                }

                string responseText = await MakeServiceRequestAsync(path, "GET", null, token);
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
            catch (NotFoundException nfe)
            {
                throw new UnregisteredUserException(destination.GetIdentifier(), nfe);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<SignedPreKeyEntity?> GetCurrentSignedPreKeyAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string responseText = await MakeServiceRequestAsync(SIGNED_PREKEY_PATH, "GET", null, token);
                return JsonUtil.FromJson<SignedPreKeyEntity>(responseText);
            }
            catch (NotFoundException ex)
            {
                logger.LogWarning(new EventId(), ex, string.Empty);
                return null;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="signedPreKey"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> SetCurrentSignedPreKeyAsync(SignedPreKeyRecord signedPreKey, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            SignedPreKeyEntity signedPreKeyEntity = new SignedPreKeyEntity(signedPreKey.getId(),
                                                                           signedPreKey.getKeyPair().getPublicKey(),
                                                                           signedPreKey.getSignature());
            await MakeServiceRequestAsync(SIGNED_PREKEY_PATH, "PUT", JsonUtil.ToJson(signedPreKeyEntity), token);
            return true;
        }

        public async Task RetrieveAttachmentAsync(int cdnNumber, SignalServiceAttachmentRemoteId cdnPath, Stream destination, int maxSizeBytes, IProgressListener? listener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string path;
            if (cdnPath.V2.HasValue)
            {
                path = string.Format(new CultureInfo("en-US"), ATTACHMENT_ID_DOWNLOAD_PATH, cdnPath.V2.Value);
            }
            else
            {
                path = string.Format(new CultureInfo("en-US"), ATTACHMENT_KEY_DOWNLOAD_PATH, cdnPath.V3);
            }

            await DownloadFromCdnAsync(destination, cdnNumber, path, maxSizeBytes, listener, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="packId"></param>
        /// <param name="stickerId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task RetrieveStickerAsync(Stream destination, byte[] packId, int stickerId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string hexPackId = Hex.ToStringCondensed(packId);
            await DownloadFromCdnAsync(destination, 0, string.Format(new CultureInfo("en-US"), STICKER_PATH, hexPackId, stickerId), 1024 * 1024, null, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="packId"></param>
        /// <param name="stickerId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<byte[]> RetrieveStickerAsync(byte[] packId, int stickerId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string hexPackId = Hex.ToStringCondensed(packId);
            MemoryStream output = new MemoryStream();

            await DownloadFromCdnAsync(output, 0, 0, string.Format(new CultureInfo("en-US"), STICKER_PATH, hexPackId, stickerId), 1024 * 1024, null, token);

            return output.ToArray();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="packId"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<byte[]> RetrieveStickerManifestAsync(byte[] packId, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string hexPackId = Hex.ToStringCondensed(packId);
            MemoryStream output = new MemoryStream();

            await DownloadFromCdnAsync(output, 0, 0, string.Format(STICKER_MANIFEST_PATH, hexPackId), 1024 * 1024, null, token);

            return output.ToArray();
        }

        public string RetrieveAttachmentDownloadUrl(int cdnNumber, SignalServiceAttachmentRemoteId cdnPath)
        {
            string path;
            if (cdnPath.V2.HasValue)
            {
                path = string.Format(new CultureInfo("en-US"), ATTACHMENT_ID_DOWNLOAD_PATH, cdnPath.V2.Value);
            }
            else
            {
                path = string.Format(new CultureInfo("en-US"), ATTACHMENT_KEY_DOWNLOAD_PATH, cdnPath.V3);
            }

            ConnectionHolder connectionHolder = GetRandom(cdnNumber == 2 ? cdn2Clients : cdnClients);
            return $"{connectionHolder.Url}/{path}";
        }

        public async Task<SignalServiceProfile> RetrieveProfileAsync(SignalServiceAddress target, UnidentifiedAccess? unidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string response = await MakeServiceRequestAsync(string.Format(PROFILE_PATH, target.GetIdentifier()), "GET", null, NO_HEADERS, EmptyResponseCodeHandler, unidentifiedAccess, token.Value);
                return JsonUtil.FromJson<SignalServiceProfile>(response);
            }
            catch (Exception e)
            {
                throw new MalformedResponseException("Unable to parse entity", e);
            }
        }

        public async Task RetrieveProfileAvatarAsync(string path, Stream destination, int maxSizeByzes, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await DownloadFromCdnAsync(destination, 0, path, maxSizeByzes, null, token);
        }

        public async Task SetProfileNameAsync(string name, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await MakeServiceRequestAsync(string.Format(PROFILE_PATH, "name/" + (name == null ? "" : WebUtility.UrlEncode(name))), "PUT", string.Empty, token);
        }

        public async Task SetProfileAvatarAsync(ProfileAvatarData? profileAvatar, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string response = await MakeServiceRequestAsync(string.Format(PROFILE_PATH, "form/avatar"), "GET", null, token);
            ProfileAvatarUploadAttributes formAttributes;

            try
            {
                formAttributes = JsonUtil.FromJson<ProfileAvatarUploadAttributes>(response);
            }
            catch (IOException e)
            {
                throw new MalformedResponseException("Unable to parse entity", e);
            }

            if (profileAvatar != null)
            {
                await UploadToCdnAsync("", formAttributes.Acl, formAttributes.Key,
                    formAttributes.Policy, formAttributes.Algorithm,
                    formAttributes.Credential, formAttributes.Date,
                    formAttributes.Signature, profileAvatar.InputData,
                    profileAvatar.ContentType, profileAvatar.DataLength,
                    profileAvatar.OutputStreamFactory, null, token);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="cdnNumber"></param>
        /// <param name="path"></param>
        /// <param name="maxSizeBytes"></param>
        /// <param name="listener"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="PushNetworkException"></exception>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        private async Task DownloadFromCdnAsync(Stream destination, int cdnNumber, string path, long maxSizeBytes, IProgressListener? listener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            await DownloadFromCdnAsync(destination, destination.Length, cdnNumber, path, maxSizeBytes, listener, token);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="destination"></param>
        /// <param name="offset"></param>
        /// <param name="cdnNumber"></param>
        /// <param name="path"></param>
        /// <param name="maxSizeBytes"></param>
        /// <param name="listener"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="PushNetworkException"></exception>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        private async Task DownloadFromCdnAsync(Stream destination, long offset, int cdnNumber, string path, long maxSizeBytes, IProgressListener? listener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConnectionHolder connectionHolder = GetRandom(cdnNumber == 2 ? cdn2Clients : cdnClients);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, new Uri($"{connectionHolder.Url}/{path}"));
            
            if (connectionHolder.HostHeader != null)
            {
                request.Headers.Host = connectionHolder.HostHeader;
            }

            if (offset > 0)
            {
                logger.LogInformation($"Starting download from CDN with offset: {offset}");
                request.Headers.Range = new RangeHeaderValue(offset, null);
            }

            HttpResponseMessage response;

            try
            {
                response = await httpClient.SendAsync(request, token.Value);

                if (response.IsSuccessStatusCode)
                {
                    HttpContent body = response.Content;

                    if (body == null) throw new PushNetworkException("No response body!");

                    try
                    {
                        await body.LoadIntoBufferAsync(maxSizeBytes);
                    }
                    catch (HttpRequestException)
                    {
                        throw new PushNetworkException("Response exceeds max size!");
                    }

                    Stream _in = await body.ReadAsStreamAsync();
                    byte[] buffer = new byte[32768];

                    int read = 0;
                    long totalRead = offset;

                    while ((read = _in.Read(buffer, 0, buffer.Length)) != 0)
                    {
                        destination.Write(buffer, 0, read);
                        if ((totalRead += read) > maxSizeBytes) throw new PushNetworkException("Response exceeded max size!");

                        if (listener != null)
                        {
                            listener.OnAttachmentProgress(body.Headers.ContentLength.HasValue ? body.Headers.ContentLength.Value + offset : 0 + offset, totalRead);
                        }
                    }

                    return;
                }
            }
            catch (IOException ex)
            {
                throw new PushNetworkException(ex);
            }

            throw new NonSuccessfulResponseCodeException((int)response.StatusCode, $"Response: {await response.Content.ReadAsStringAsync()}");
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="path"></param>
        /// <param name="acl"></param>
        /// <param name="key"></param>
        /// <param name="policy"></param>
        /// <param name="algorithm"></param>
        /// <param name="credential"></param>
        /// <param name="date"></param>
        /// <param name="signature"></param>
        /// <param name="data"></param>
        /// <param name="contentType"></param>
        /// <param name="length"></param>
        /// <param name="outputStreamFactory"></param>
        /// <param name="progressListener"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="PushNetworkException"></exception>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        private async Task<byte[]> UploadToCdnAsync(string path, string acl, string key, string policy, string algorithm,
            string credential, string date, string signature,
            Stream data, string contentType, long length,
            IOutputStreamFactory outputStreamFactory, IProgressListener? progressListener,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConnectionHolder connectionHolder = GetRandom(cdnClients);

            MemoryStream tmpStream = new MemoryStream();
            DigestingOutputStream outputStream = outputStreamFactory.CreateFor(tmpStream);
            data.CopyTo(outputStream);
            outputStream.Flush();
            tmpStream.Position = 0;
            StreamContent streamContent = new StreamContent(tmpStream);

            // Passing this to requestBody currently fails due to a bug in HttpClient when using UWP streams. This
            // isn't a huge deal though because we will switch to all V3 attachments in a later commit.
            DigestingRequestBody file = new DigestingRequestBody(data, outputStreamFactory, contentType, length, progressListener, token);

            MultipartFormDataContent requestBody = new MultipartFormDataContent();
            requestBody.Add(new StringContent(acl), "acl");
            requestBody.Add(new StringContent(key), "key");
            requestBody.Add(new StringContent(policy), "policy");
            requestBody.Add(new StringContent(contentType), "Content-Type");
            requestBody.Add(new StringContent(algorithm), "x-amz-algorithm");
            requestBody.Add(new StringContent(credential), "x-amz-credential");
            requestBody.Add(new StringContent(date), "x-amz-date");
            requestBody.Add(new StringContent(signature), "x-amz-signature");
            requestBody.Add(streamContent, "file", "file");

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, new Uri($"{connectionHolder.Url}/{path}"));
            request.Content = requestBody;

            if (connectionHolder.HostHeader != null)
            {
                request.Headers.Host = connectionHolder.HostHeader;
            }

            HttpResponseMessage response;

            try
            {
                response = await httpClient.SendAsync(request, token.Value);
            }
            catch (Exception ex)
            {
                throw new PushNetworkException(ex);
            }

            if (response.IsSuccessStatusCode) return outputStream.GetTransmittedDigest();
            else throw new NonSuccessfulResponseCodeException((int)response.StatusCode, $"Response: {await response.Content.ReadAsStringAsync()}");
        }

        private async Task<string> GetResumableUploadUrlAsync(string signedUrl, Dictionary<string, string> headers, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConnectionHolder connectionHolder = GetRandom(cdn2Clients);
            Uri endpointUrl = new Uri(connectionHolder.Url);
            Uri signedHttpUrl;
            try
            {
                signedHttpUrl = new Uri(signedUrl);
            }
            catch (UriFormatException ex)
            {
                logger.LogTrace(new EventId(), ex, $"Server returned a malformed signed url: {signedUrl}");
                throw new IOException("Server returned a malformed signed url", ex);
            }

            UriBuilder urlBuilder = new UriBuilder(endpointUrl.Scheme, endpointUrl.Host, endpointUrl.Port);
            urlBuilder.Path = Path.Combine(endpointUrl.LocalPath, signedHttpUrl.LocalPath.Substring(1));
            urlBuilder.Query = signedHttpUrl.Query.Substring(1); // for some reason the "?" is already on the Query so setting the urlBuilder.Query will cause the url to have 2 ??s
            urlBuilder.Fragment = signedHttpUrl.Fragment;

            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Post, urlBuilder.Uri);
            request.Content = new StringContent("");
            foreach (var header in headers)
            {
                if (header.Key.ToLower() != "host")
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            if (connectionHolder.HostHeader != null)
            {
                request.Headers.Host = connectionHolder.HostHeader;
            }

            HttpResponseMessage response;

            try
            {
                response = await httpClient.SendAsync(request, token.Value);
            }
            catch (Exception ex)
            {
                throw new PushNetworkException(ex);
            }

            if (response.IsSuccessStatusCode)
            {
                return response.Headers.GetValues("location").First();
            }
            else
            {
                throw new NonSuccessfulResponseCodeException((int)response.StatusCode, $"Response: {await response.Content.ReadAsStringAsync()}");
            }
        }

        private async Task<byte[]> UploadToCdn2Async(string resumableUrl, Stream data, string contentType, long length, IOutputStreamFactory outputStreamFactory, IProgressListener? progressListener, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConnectionHolder connectionHolder = GetRandom(cdn2Clients);

            DigestingRequestBody file = new DigestingRequestBody(data, outputStreamFactory, contentType, length, progressListener, token);
            HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Put, resumableUrl);
            request.Content = file;

            if (connectionHolder.HostHeader != null)
            {
                request.Headers.Host = connectionHolder.HostHeader;
            }

            HttpResponseMessage response;

            try
            {
                response = await httpClient.SendAsync(request, token.Value);
            }
            catch (Exception ex)
            {
                throw new PushNetworkException(ex);
            }

            if (response.IsSuccessStatusCode)
            {
                return file.GetTransmittedDigest();
            }
            else
            {
                throw new NonSuccessfulResponseCodeException((int)response.StatusCode, $"Response: {await response.Content.ReadAsStringAsync()}");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="contactTokens"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<List<ContactTokenDetails>> RetrieveDirectoryAsync(ICollection<string> contactTokens, CancellationToken? token = null) // TODO: whacky
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ContactTokenList contactTokenList = new ContactTokenList(contactTokens.ToList());
            string response = await MakeServiceRequestAsync(DIRECTORY_TOKENS_PATH, "PUT", JsonUtil.ToJson(contactTokenList), token);
            ContactTokenDetailsList activeTokens = JsonUtil.FromJson<ContactTokenDetailsList>(response);

            return activeTokens.Contacts;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="contactToken"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        public async Task<ContactTokenDetails?> GetContactTokenDetailsAsync(string contactToken, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                string response = await MakeServiceRequestAsync(string.Format(DIRECTORY_VERIFY_PATH, contactToken), "GET", null, token);
                return JsonUtil.FromJson<ContactTokenDetails>(response);
            }
            catch (Exception)
            {
                return null;
            }
        }

        public async Task<string> GetContactDiscoveryAuthorizationAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string response = await MakeServiceRequestAsync(DIRECTORY_AUTH_PATH, "GET", null, token);
            ContactDiscoveryCredentials credentials = JsonUtil.FromJson<ContactDiscoveryCredentials>(response);
            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{credentials.Username}:{credentials.Password}"))).ToString();
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
        public async Task<DiscoveryResponse> GetContactDiscoveryRegisteredUsersAsync(string authorizationToken, DiscoveryRequest request, IList<string> cookies, string mrenclave, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            HttpContent body = (await MakeRequestAsync(ClientSet.ContactDiscovery, authorizationToken, cookies, $"/v1/discovery/{mrenclave}", "PUT", JsonUtil.ToJson(request), token)).Content;

            if (body != null)
            {
                return JsonUtil.FromJson<DiscoveryResponse>(await body.ReadAsStringAsync());
            }
            else
            {
                throw new MalformedResponseException("Empty response!");
            }
        }

        public async Task<TurnServerInfo> GetTurnServerInfoAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string response = await MakeServiceRequestAsync(TURN_SERVER_INFO, "GET", null, token);
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

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<AttachmentV2UploadAttributes> GetAttachmentV2UploadAttributesAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string response = await MakeServiceRequestAsync(ATTACHMENT_V2_PATH, "GET", null, token);

            try
            {
                return JsonUtil.FromJson<AttachmentV2UploadAttributes>(response);
            }
            catch (JsonParseException ex)
            {
                logger.LogTrace(new EventId(), ex, string.Empty);
                throw new NonSuccessfulResponseCodeException(500, "Unable to parse entity");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        public async Task<AttachmentV3UploadAttributes> GetAttachmentV3UploadAttributesAsync(CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string response = await MakeServiceRequestAsync(ATTACHMENT_V3_PATH, "GET", null, token);

            try
            {
                return JsonUtil.FromJson<AttachmentV3UploadAttributes>(response);
            }
            catch (JsonParseException ex)
            {
                logger.LogTrace(new EventId(), ex, string.Empty);
                throw new NonSuccessfulResponseCodeException(500, "Unable to parse entity");
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="attachment"></param>
        /// <param name="uploadAttributes"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="PushNetworkException"></exception>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        public async Task<(long, byte[])> UploadAttachmentAsync(PushAttachmentData attachment, AttachmentV2UploadAttributes uploadAttributes,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            long id = long.Parse(uploadAttributes.AttachmentId);
            byte[] digest = await UploadToCdnAsync(ATTACHMENT_UPLOAD_PATH, uploadAttributes.Acl!, uploadAttributes.Key!,
                uploadAttributes.Policy!, uploadAttributes.Algorithm!,
                uploadAttributes.Credential!, uploadAttributes.Date!,
                uploadAttributes.Signature!, attachment.Data,
                "application/octet-stream", attachment.DataSize,
                attachment.OutputFactory, attachment.Listener,
                token);

            return (id, digest);
        }

        public async Task<byte[]> UploadAttachmentAsync(PushAttachmentData attachment, AttachmentV3UploadAttributes uploadAttributes,
            CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            string resumableUploadUrl = await GetResumableUploadUrlAsync(uploadAttributes.SignedUploadLocation!, uploadAttributes.Headers!, token);
            return await UploadToCdn2Async(resumableUploadUrl,
                attachment.Data,
                "application/octet-stream",
                attachment.DataSize,
                attachment.OutputFactory,
                attachment.Listener,
                token);
        }

        private async Task<string> MakeServiceRequestAsync(string urlFragment, string method, string? body, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            return await MakeServiceRequestAsync(urlFragment, method, body, NO_HEADERS, EmptyResponseCodeHandler, null, token);
        }

        private async Task<string> MakeServiceRequestAsync(string urlFragment, string method, string? body, Dictionary<string, string> headers, Action<int>? responseCodeHandler = null, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            if (responseCodeHandler == null)
            {
                responseCodeHandler = EmptyResponseCodeHandler;
            }

            return await MakeServiceRequestAsync(urlFragment, method, body, headers, responseCodeHandler, null, token);
        }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="urlFragment"></param>
        /// <param name="method"></param>
        /// <param name="body"></param>
        /// <param name="unidentifiedAccess"></param>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="NonSuccessfulResponseCodeException"></exception>
        /// <exception cref="PushNetworkException"></exception>
        /// <exception cref="MalformedResponseException"></exception>
        private async Task<string> MakeServiceRequestAsync(string urlFragment, string method, string? body, Dictionary<string, string> headers, Action<int> responseCodeHandler, UnidentifiedAccess? unidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            HttpResponseMessage connection = await GetServiceConnectionAsync(urlFragment, method, body, headers, unidentifiedAccess, token.Value);
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
                logger.LogError("MakeServiceRequestAsync failed: {0}\n{1}", ioe.Message, ioe.StackTrace);
                throw new PushNetworkException(ioe);
            }

            responseCodeHandler.Invoke((int)responseCode);

            switch ((uint)responseCode)
            {
                case 413: // HttpStatusCode.RequestEntityTooLarge
                    throw new RateLimitException("Rate limit exceeded: " + responseCode);
                case 401: // HttpStatusCode.Unauthorized
                case 403: // HttpStatusCode.Forbidden
                    throw new AuthorizationFailedException((int)responseCode, "Authorization failed!");
                case 404: // HttpStatusCode.NotFound
                    throw new NotFoundException("Not found");
                case 409: // HttpStatusCode.Conflict
                    MismatchedDevices mismatchedDevices;
                    try
                    {
                        mismatchedDevices = JsonUtil.FromJson<MismatchedDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        logger.LogError("MakeServiceRequestAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new MismatchedDevicesException(mismatchedDevices);
                case 410: // HttpStatusCode.Gone
                    StaleDevices staleDevices;
                    try
                    {
                        staleDevices = JsonUtil.FromJson<StaleDevices>(responseBody);
                    }
                    catch (Exception e)
                    {
                        logger.LogError("MakeServiceRequestAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                        throw new PushNetworkException(e);
                    }
                    throw new StaleDevicesException(staleDevices);
                case 411: //HttpStatusCode.LengthRequired
                    DeviceLimit deviceLimit;
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
                throw new NonSuccessfulResponseCodeException((int)responseCode,
                    $"Bad response: {(int)responseCode} {responseMessage}");
            }

            return responseBody;
        }

        private async Task<HttpResponseMessage> GetServiceConnectionAsync(string urlFragment, string method, string? body, Dictionary<string, string> headers, UnidentifiedAccess? unidentifiedAccess, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            try
            {
                SignalUrl signalUrl = GetRandom(signalConnectionInformation.SignalServiceUrls);
                string url = signalUrl.Url;
                string? hostHeader = signalUrl.HostHeader;
                Uri uri = new Uri(string.Format("{0}{1}", url, urlFragment));
                HttpRequestMessage request = new HttpRequestMessage(new HttpMethod(method), uri);

                if (body != null)
                {
                    request.Content = new StringContent(body, Encoding.UTF8, "application/json");
                }

                HttpRequestHeaders requestHeaders = request.Headers;

                foreach (var header in headers)
                {
                    requestHeaders.Add(header.Key, header.Value);
                }

                if (unidentifiedAccess != null)
                {
                    requestHeaders.Add("Unidentified-Access-Key", Base64.EncodeBytes(unidentifiedAccess.UnidentifiedAccessKey));
                }
                if (credentialsProvider.Password != null)
                {
                    string authHeader = GetAuthorizationHeader(credentialsProvider);
                    requestHeaders.Add("Authorization", authHeader);
                }

                if (userAgent != null)
                {
                    requestHeaders.Add("X-Signal-Agent", userAgent);
                }

                if (hostHeader != null)
                {
                    requestHeaders.Host = hostHeader;
                }

                return await httpClient.SendAsync(request, token.Value);
            }
            catch (Exception e)
            {
                logger.LogError("GetServiceConnectionAsync() failed: {0}\n{1}", e.Message, e.StackTrace);
                throw new PushNetworkException(e);
            }
        }

        private ConnectionHolder[] ClientsFor(ClientSet clientSet)
        {
            if (clientSet == ClientSet.ContactDiscovery)
            {
                return contactDiscoveryClients;
            }
            else if (clientSet == ClientSet.KeyBackup)
            {
                throw new NotImplementedException("Needs to be implemented.");
            }
            else
            {
                throw new InvalidOperationException("Unknown attestation purpose");
            }
        }

        public async Task<HttpResponseMessage> MakeRequestAsync(ClientSet clientSet, string authorization, IList<string> cookies, string path, string method, string body, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            ConnectionHolder connectionHolder = GetRandom(ClientsFor(clientSet));
            return await MakeRequestAsync(connectionHolder, authorization, cookies, path, method, body, token);
        }

        private async Task<HttpResponseMessage> MakeRequestAsync(ConnectionHolder connectionHolder, string? authorization, IList<string>? cookies, string path, string method, string body, CancellationToken? token = null)
        {
            if (token == null)
            {
                token = CancellationToken.None;
            }

            HttpClient client = connectionHolder.Client;
            HttpRequestMessage request = new HttpRequestMessage(new HttpMethod(method), $"{connectionHolder.Url}{path}");

            if (body != null)
            {
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            HttpRequestHeaders headers = request.Headers;
            
            if (connectionHolder.HostHeader != null)
            {
                headers.Host = connectionHolder.HostHeader;
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
                response = await client.SendAsync(request, token.Value);

                if (response.IsSuccessStatusCode)
                {
                    return response;
                }
            }
            catch (Exception ex)
            {
                throw new PushNetworkException(ex);
            }

            switch ((int)response.StatusCode)
            {
                case 401:
                case 403:
                    throw new AuthorizationFailedException((int)response.StatusCode, "Authorization failed!");
                case 409:
                    throw new RemoteAttestationResponseExpiredException("Remote attestation response expired");
                case 429:
                    throw new RateLimitException($"Rate limit exceeded: {response.StatusCode}");
            }

            if (response.Content != null)
            {
                throw new NonSuccessfulResponseCodeException((int)response.StatusCode,
                    $"Response: {await response.Content.ReadAsStringAsync()}");
            }
            else
            {
                throw new NonSuccessfulResponseCodeException((int)response.StatusCode, $"Response: null");
            }
        }

        private ConnectionHolder[] CreateConnectionHolders(SignalUrl[] urls)
        {
            List<ConnectionHolder> connectionHolder = new List<ConnectionHolder>();
            foreach (SignalUrl url in urls)
            {
                connectionHolder.Add(new ConnectionHolder(httpClient, url.Url, url.HostHeader));
            }
            return connectionHolder.ToArray();
        }

        private string GetAuthorizationHeader(ICredentialsProvider provider)
        {
            string? identifier = credentialsProvider.Uuid.HasValue ? credentialsProvider.Uuid.Value.ToString() : credentialsProvider.E164;
            if (provider.DeviceId == SignalServiceAddress.DEFAULT_DEVICE_ID)
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((identifier + ":" + provider.Password)));
            }
            else
            {
                return "Basic " + Base64.EncodeBytes(Encoding.UTF8.GetBytes((identifier + "." + provider.DeviceId + ":" + provider.Password)));
            }
        }

        private T GetRandom<T>(T[] connections)
        {
            return connections[Util.generateRandomNumber() % connections.Length];
        }

        private void EmptyResponseCodeHandler(int responseCode)
        {
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

    internal class ConnectionHolder
    {
        public HttpClient Client { get; }
        public string Url { get; }
        public string? HostHeader { get; }

        public ConnectionHolder(HttpClient client, string url, string? hostHeader)
        {
            Client = client;
            Url = url;
            HostHeader = hostHeader;
        }
    }
}
