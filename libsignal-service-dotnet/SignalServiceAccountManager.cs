using Google.Protobuf;
using libsignal;
using libsignal.ecc;
using libsignal.push;
using libsignal.state;
using libsignal.util;
using libsignal_service_dotnet.messages.calls;
using libsignalservice.configuration;
using libsignalservice.crypto;
using libsignalservice.messages.multidevice;
using libsignalservice.push;
using libsignalservice.push.http;
using libsignalservice.util;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace libsignalservice
{
    /// <summary>
    /// The main interface for creating, registering, and
    /// managing a TextSecure account.
    /// </summary>
    public class SignalServiceAccountManager
    {
        private PushServiceSocket PushServiceSocket;
        private static ProvisioningSocket ProvisioningSocket;
        private SignalServiceConfiguration Configuration;
        private readonly string User;
        private readonly string UserAgent;

        /// <summary>
        /// Construct a SignalServivceAccountManager
        /// </summary>
        /// <param name="configuration">The URL configuration for the Signal Service</param>
        /// <param name="user">A Signal Service phone number</param>
        /// <param name="password">A Signal Service password</param>
        /// <param name="deviceId">A Signal Service device id</param>
        /// <param name="userAgent">A string which identifies the client software</param>
        public SignalServiceAccountManager(SignalServiceConfiguration configuration,
                                        string user, string password, int deviceId, string userAgent)
        {
            PushServiceSocket = new PushServiceSocket(configuration, new StaticCredentialsProvider(user, password, null, deviceId), userAgent);
            User = user;
            UserAgent = userAgent;
        }

        public SignalServiceAccountManager(SignalServiceConfiguration configuration, CancellationToken token, string userAgent)
        {
            Configuration = configuration;
            UserAgent = userAgent;
            ProvisioningSocket = new ProvisioningSocket(configuration.SignalServiceUrls[0].Url, token);
            PushServiceSocket = new PushServiceSocket(configuration, new StaticCredentialsProvider(null, null, null, (int)SignalServiceAddress.DEFAULT_DEVICE_ID), userAgent);
        }

        /// <summary>
        /// Register/Unregister a Google Cloud Messaging registration ID.
        /// </summary>
        /// <param name="gcmRegistrationId">The GCM id to register.  A call with an absent value will unregister.</param>
        /// <returns></returns>
        public void SetGcmId(May<string> gcmRegistrationId)// throws IOException
        {
            if (gcmRegistrationId.HasValue)
            {
                this.PushServiceSocket.registerGcmId(gcmRegistrationId.ForceGetValue());
            }
            else
            {
                this.PushServiceSocket.unregisterGcmId();
            }
        }

        /// <summary>
        /// Request an SMS verification code.  On success, the server will send
        /// an SMS verification code to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void RequestSmsVerificationCode()// throws IOException
        {
            this.PushServiceSocket.CreateAccount(false);
        }

        /// <summary>
        /// Request a Voice verification code.  On success, the server will
        /// make a voice call to this Signal user.
        /// </summary>
        /// <returns></returns>
        public void RequestVoiceVerificationCode()// throws IOException
        {
            this.PushServiceSocket.CreateAccount(true);
        }

        /// <summary>
        /// Verify a Signal Service account with a received SMS or voice verification code.
        /// </summary>
        /// <param name="verificationCode">The verification code received via SMS or Voice
        /// <see cref="RequestSmsVerificationCode()"/> and <see cref="RequestVoiceVerificationCode()"/></param>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this Signal install.
        /// This value should remain consistent across registrations for the
        /// same install, but probabilistically differ across registrations
        /// for separate installs.</param>
        /// <returns></returns>
        public void VerifyAccountWithCode(string verificationCode, string signalingKey,
                                   uint signalProtocolRegistrationId, bool fetchesMessages)
        {
            this.PushServiceSocket.VerifyAccountCode(verificationCode, signalingKey,
                                                 signalProtocolRegistrationId, fetchesMessages);
        }

        /// <summary>
        /// Refresh account attributes with server.
        /// </summary>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this TextSecure install.
        /// This value should remain consistent across registrations for the same
        /// install, but probabilistically differ across registrations for
        /// separate installs.</param>
        /// <param name="voice">A boolean that indicates whether the client supports secure voice (RedPhone)</param>
        /// <returns></returns>
        public void SetAccountAttributes(string signalingKey, uint signalProtocolRegistrationId, bool fetchesMessages)
        {
            this.PushServiceSocket.SetAccountAttributes(signalingKey, signalProtocolRegistrationId, fetchesMessages);
        }

        /// <summary>
        /// Register an identity key, signed prekey, and list of one time prekeys
        /// with the server.
        /// </summary>
        /// <param name="identityKey">The client's long-term identity keypair.</param>
        /// <param name="signedPreKey">The client's signed prekey.</param>
        /// <param name="oneTimePreKeys">The client's list of one-time prekeys.</param>
        /// <returns></returns>
        public bool SetPreKeys(IdentityKey identityKey, SignedPreKeyRecord signedPreKey, IList<PreKeyRecord> oneTimePreKeys)//throws IOException
        {
            this.PushServiceSocket.registerPreKeys(identityKey, signedPreKey, oneTimePreKeys);
            return true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's count of currently available (eg. unused) prekeys for this user.</returns>
        public int GetPreKeysCount()// throws IOException
        {
            return this.PushServiceSocket.getAvailablePreKeys();
        }

        /// <summary>
        /// Set the client's signed prekey.
        /// </summary>
        /// <param name="signedPreKey">The client's new signed prekey.</param>
        public void SetSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            this.PushServiceSocket.setCurrentSignedPreKey(signedPreKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's view of the client's current signed prekey.</returns>
        public SignedPreKeyEntity GetSignedPreKey()// throws IOException
        {
            return this.PushServiceSocket.getCurrentSignedPreKey();
        }

        /// <summary>
        /// Checks whether a contact is currently registered with the server.
        /// </summary>
        /// <param name="e164number">The contact to check.</param>
        /// <returns>An optional ContactTokenDetails, present if registered, absent if not.</returns>
        public May<ContactTokenDetails> GetContact(string e164number)// throws IOException
        {
            string contactToken = CreateDirectoryServerToken(e164number, true);
            ContactTokenDetails contactTokenDetails = this.PushServiceSocket.getContactTokenDetails(contactToken);

            if (contactTokenDetails != null)
            {
                contactTokenDetails.setNumber(e164number);
            }

            return new May<ContactTokenDetails>(contactTokenDetails);
        }

        /// <summary>
        /// Checks which contacts in a set are registered with the server.
        /// </summary>
        /// <param name="e164numbers">The contacts to check.</param>
        /// <returns>A list of ContactTokenDetails for the registered users.</returns>
        public List<ContactTokenDetails> GetContacts(IList<string> e164numbers)
        {
            IDictionary<string, string> contactTokensMap = CreateDirectoryServerTokenMap(e164numbers);
            List<ContactTokenDetails> activeTokens = this.PushServiceSocket.retrieveDirectory(contactTokensMap.Keys);

            foreach (ContactTokenDetails activeToken in activeTokens)
            {
                string number;
                contactTokensMap.TryGetValue(activeToken.getToken(), out number);
                activeToken.setNumber(number);
            }

            return activeTokens;
        }

        public string GetAccountVerificationToken()
        {
            return this.PushServiceSocket.getAccountVerificationToken();
        }

        public string GetNewDeviceUuid(CancellationToken token)
        {
            ProvisioningSocket = new ProvisioningSocket(Configuration.SignalServiceUrls[0].Url, token);
            return ProvisioningSocket.GetProvisioningUuid().Uuid;
        }

        public string GetNewDeviceVerificationCode()// throws IOException
        {
            return this.PushServiceSocket.getNewDeviceVerificationCode();
        }

        public NewDeviceLinkResult FinishNewDeviceRegistration(IdentityKeyPair tempIdentity, string signalingKey, string password, bool sms, bool fetches, int regid, string name)
        {
            ProvisionMessage pm = ProvisioningSocket.GetProvisioningMessage(tempIdentity);
            string provisioningCode = pm.ProvisioningCode;
            byte[] publicKeyBytes = pm.IdentityKeyPublic.ToByteArray();
            if (publicKeyBytes.Length == 32)
            {
                byte[] type = { Curve.DJB_TYPE };
                publicKeyBytes = ByteUtil.combine(type, publicKeyBytes);
            }
            ECPublicKey publicKey = Curve.decodePoint(publicKeyBytes, 0);
            byte[] privateKeyBytes = pm.IdentityKeyPrivate.ToByteArray();
            ECPrivateKey privateKey = Curve.decodePrivatePoint(privateKeyBytes);
            IdentityKeyPair identity = new IdentityKeyPair(new IdentityKey(publicKey), privateKey);
            PushServiceSocket = new PushServiceSocket(Configuration, new StaticCredentialsProvider(pm.Number, password, null, -1), UserAgent);
            int deviceId = PushServiceSocket.finishNewDeviceRegistration(provisioningCode, signalingKey, sms, fetches, regid, name);
            return new NewDeviceLinkResult()
            {
                DeviceId = deviceId,
                Identity = identity,
                Number = pm.Number
            };
        }

        public void AddDevice(string deviceIdentifier,
                              ECPublicKey deviceKey,
                              IdentityKeyPair identityKeyPair,
                              string code)//throws InvalidKeyException, IOException
        {
            ProvisioningCipher cipher = new ProvisioningCipher(deviceKey);
            ProvisionMessage message = new ProvisionMessage
            {
                IdentityKeyPublic = ByteString.CopyFrom(identityKeyPair.getPublicKey().serialize()),
                IdentityKeyPrivate = ByteString.CopyFrom(identityKeyPair.getPrivateKey().serialize()),
                Number = User,
                ProvisioningCode = code
            };

            byte[] ciphertext = cipher.encrypt(message);
            this.PushServiceSocket.sendProvisioningMessage(deviceIdentifier, ciphertext);
        }

        public List<DeviceInfo> GetDevices()
        {
            return this.PushServiceSocket.getDevices();
        }

        public void RemoveDevice(long deviceId)
        {
            this.PushServiceSocket.removeDevice(deviceId);
        }

        public TurnServerInfo GetTurnServerInfo()
        {
            return this.PushServiceSocket.getTurnServerInfo();
        }

        public void SetProfileName(byte[] key, string name)
        {
            String ciphertextName = null;
            if (name != null)
            {
                ciphertextName = Base64.encodeBytesWithoutPadding(new ProfileCipher(key).Encrypt(Encoding.Unicode.GetBytes(name), ProfileCipher.NAME_PADDED_LENGTH));
            }
            PushServiceSocket.SetProfileName(ciphertextName);
        }

        public void SetProfileAvatar(byte[] key, StreamDetails avatar)
        {
            ProfileAvatarData profileAvatarData = null;
            if (avatar != null)
            {
                profileAvatarData = new ProfileAvatarData(avatar.InputStream, avatar.Length, avatar.ContentType, new ProfileCipherOutputStreamFactory(key));
            }
            PushServiceSocket.SetProfileAvatar(profileAvatarData);
        }

        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            this.PushServiceSocket.setSoTimeoutMillis(soTimeoutMillis);
        }

        public void CancelInFlightRequests()
        {
            this.PushServiceSocket.cancelInFlightRequests();
        }

        private string CreateDirectoryServerToken(string e164number, bool urlSafe)
        {
            try
            {
                byte[] token = Util.trim(Hash.sha1(Encoding.UTF8.GetBytes(e164number)), 10);
                string encoded = Base64.encodeBytesWithoutPadding(token);

                if (urlSafe) return encoded.Replace('+', '-').Replace('/', '_');
                else return encoded;
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private IDictionary<string, string> CreateDirectoryServerTokenMap(IList<string> e164numbers)
        {
            IDictionary<string, string> tokenMap = new Dictionary<string, string>(e164numbers.Count);

            foreach (string number in e164numbers)
            {
                var token = CreateDirectoryServerToken(number, false);
                if (!tokenMap.ContainsKey(token)) // mimic java set behaviour
                {
                    tokenMap.Add(token, number);
                }
            }

            return tokenMap;
        }
    }

    public class NewDeviceLinkResult
    {
        public IdentityKeyPair Identity { get; set; }
        public int DeviceId { get; set; }
        public string Number { get; set; }
    }
}
