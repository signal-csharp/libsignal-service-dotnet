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
using System.Threading.Tasks;

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

        /// <summary>
        /// Construct a SignalServiceAccountManager for linking as a slave device
        /// </summary>
        /// <param name="configuration">The URL configuration for the Signal Service</param>
        /// <param name="token">The cancellation token for the ProvisioningSocket</param>
        /// <param name="userAgent">A string which identifies the client software</param>
        public SignalServiceAccountManager(SignalServiceConfiguration configuration, string userAgent)
        {
            Configuration = configuration;
            UserAgent = userAgent;
            ProvisioningSocket = new ProvisioningSocket(configuration.SignalServiceUrls[0].Url);
            PushServiceSocket = new PushServiceSocket(configuration, new StaticCredentialsProvider(null, null, null, (int)SignalServiceAddress.DEFAULT_DEVICE_ID), userAgent);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pin"></param>
        public void SetPin(string pin)
        {
            if (pin != null)
                PushServiceSocket.SetPin(pin);
            else
                PushServiceSocket.RemovePin();
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
                this.PushServiceSocket.RegisterGcmId(gcmRegistrationId.ForceGetValue());
            }
            else
            {
                this.PushServiceSocket.UnregisterGcmId();
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
        /// <param name="fetchesMessages">True if the client does not support GCM</param>
        /// <param name="pin"></param>
        /// <returns></returns>
        public void VerifyAccountWithCode(string verificationCode, string signalingKey,
                                   uint signalProtocolRegistrationId, bool fetchesMessages, string pin)
        {
            this.PushServiceSocket.VerifyAccountCode(verificationCode, signalingKey,
                                                 signalProtocolRegistrationId, fetchesMessages, pin);
        }

        /// <summary>
        /// Refresh account attributes with server.
        /// </summary>
        /// <param name="signalingKey">52 random bytes.  A 32 byte AES key and a 20 byte Hmac256 key, concatenated.</param>
        /// <param name="signalProtocolRegistrationId">A random 14-bit number that identifies this TextSecure install.
        /// This value should remain consistent across registrations for the same
        /// install, but probabilistically differ across registrations for
        /// separate installs.</param>
        /// <param name="fetchesMessages">True if the client does not support GCM</param>
        /// <param name="pin"></param>
        /// <returns></returns>
        public void SetAccountAttributes(string signalingKey, uint signalProtocolRegistrationId, bool fetchesMessages, string pin)
        {
            this.PushServiceSocket.SetAccountAttributes(signalingKey, signalProtocolRegistrationId, fetchesMessages, pin);
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
            this.PushServiceSocket.RegisterPreKeys(identityKey, signedPreKey, oneTimePreKeys);
            return true;
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's count of currently available (eg. unused) prekeys for this user.</returns>
        public int GetPreKeysCount()// throws IOException
        {
            return this.PushServiceSocket.GetAvailablePreKeys();
        }

        /// <summary>
        /// Set the client's signed prekey.
        /// </summary>
        /// <param name="signedPreKey">The client's new signed prekey.</param>
        public void SetSignedPreKey(SignedPreKeyRecord signedPreKey)// throws IOException
        {
            this.PushServiceSocket.SetCurrentSignedPreKey(signedPreKey);
        }

        /// <summary>
        ///
        /// </summary>
        /// <returns>The server's view of the client's current signed prekey.</returns>
        public SignedPreKeyEntity GetSignedPreKey()// throws IOException
        {
            return this.PushServiceSocket.GetCurrentSignedPreKey();
        }

        /// <summary>
        /// Checks whether a contact is currently registered with the server
        /// </summary>
        /// <param name="e164number">The contact to check.</param>
        /// <returns>An optional ContactTokenDetails, present if registered, absent if not.</returns>
        public May<ContactTokenDetails> GetContact(string e164number)// throws IOException
        {
            string contactToken = CreateDirectoryServerToken(e164number, true);
            ContactTokenDetails contactTokenDetails = this.PushServiceSocket.GetContactTokenDetails(contactToken);

            if (contactTokenDetails != null)
            {
                contactTokenDetails.Number = e164number;
            }

            return new May<ContactTokenDetails>(contactTokenDetails);
        }

        /// <summary>
        /// Checks which contacts in a set are registered with the server
        /// </summary>
        /// <param name="e164numbers">The contacts to check.</param>
        /// <returns>A list of ContactTokenDetails for the registered users.</returns>
        public List<ContactTokenDetails> GetContacts(IList<string> e164numbers)
        {
            IDictionary<string, string> contactTokensMap = CreateDirectoryServerTokenMap(e164numbers);
            List<ContactTokenDetails> activeTokens = this.PushServiceSocket.RetrieveDirectory(contactTokensMap.Keys);

            foreach (ContactTokenDetails activeToken in activeTokens)
            {
                contactTokensMap.TryGetValue(activeToken.Token, out string number);
                activeToken.Number = number;
            }

            return activeTokens;
        }

        /// <summary>
        /// Request a UUID from the server for linking as a new device.
        /// Called by the new device.
        /// </summary>
        /// <param name="token">The UUID, Base64 encoded</param>
        /// <returns></returns>
        public async Task<string> GetNewDeviceUuid(CancellationToken token)
        {
            ProvisioningSocket = new ProvisioningSocket(Configuration.SignalServiceUrls[0].Url);
            return (await ProvisioningSocket.GetProvisioningUuid(token)).Uuid;
        }

        /// <summary>
        /// Request a code for verification of a new device.
        /// Called by an already verified device.
        /// </summary>
        /// <returns>A verification code (String of 6 digits)</returns>
        public string GetNewDeviceVerificationCode()// throws IOException
        {
            return this.PushServiceSocket.GetNewDeviceVerificationCode();
        }

        /// <summary>
        /// Fetch a ProvisionMessage from the server.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="tempIdentity"></param>
        /// <returns></returns>
        public async Task<SignalServiceProvisionMessage> GetProvisioningMessage(CancellationToken token, IdentityKeyPair tempIdentity)
        {
            ProvisionMessage protoPm = await ProvisioningSocket.GetProvisioningMessage(token, tempIdentity);
            string provisioningCode = protoPm.ProvisioningCode;
            byte[] publicKeyBytes = protoPm.IdentityKeyPublic.ToByteArray();
            if (publicKeyBytes.Length == 32)
            {
                byte[] type = { Curve.DJB_TYPE };
                publicKeyBytes = ByteUtil.combine(type, publicKeyBytes);
            }
            ECPublicKey publicKey = Curve.decodePoint(publicKeyBytes, 0);
            byte[] privateKeyBytes = protoPm.IdentityKeyPrivate.ToByteArray();
            ECPrivateKey privateKey = Curve.decodePrivatePoint(privateKeyBytes);
            IdentityKeyPair identity = new IdentityKeyPair(new IdentityKey(publicKey), privateKey);
            return new SignalServiceProvisionMessage()
            {
                Number = protoPm.Number,
                Identity = identity,
                Code = protoPm.ProvisioningCode
            };
        }

        /// <summary>
        /// Finishes a registration as a new device.
        /// Called by the new device. This method blocks until the already verified device has verified this device.
        /// </summary>
        /// <param name="token"></param>
        /// <param name="provisionMessage"></param>
        /// <param name="signalingKey"></param>
        /// <param name="password"></param>
        /// <param name="sms"></param>
        /// <param name="fetches"></param>
        /// <param name="regid"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<int> FinishNewDeviceRegistration(CancellationToken token, SignalServiceProvisionMessage provisionMessage, string signalingKey, string password, bool sms, bool fetches, int regid, string name)
        {
            PushServiceSocket = new PushServiceSocket(Configuration, new StaticCredentialsProvider(provisionMessage.Number, password, null, -1), UserAgent);
            return await PushServiceSocket.FinishNewDeviceRegistration(token, provisionMessage.Code, signalingKey, sms, fetches, regid, name);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="deviceIdentifier"></param>
        /// <param name="deviceKey"></param>
        /// <param name="identityKeyPair"></param>
        /// <param name="profileKey"></param>
        /// <param name="code"></param>
        public void AddDevice(string deviceIdentifier,
                              ECPublicKey deviceKey,
                              IdentityKeyPair identityKeyPair,
                              byte[] profileKey,
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

            if (profileKey != null)
            {
                message.ProfileKey = ByteString.CopyFrom(profileKey);
            }

            byte[] ciphertext = cipher.encrypt(message);
            this.PushServiceSocket.SendProvisioningMessage(deviceIdentifier, ciphertext);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <returns></returns>
        public List<DeviceInfo> GetDevices()
        {
            return this.PushServiceSocket.GetDevices();
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="deviceId"></param>
        public void RemoveDevice(long deviceId)
        {
            this.PushServiceSocket.RemoveDevice(deviceId);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <returns></returns>
        public async Task<TurnServerInfo> GetTurnServerInfo(CancellationToken token)
        {
            return await this.PushServiceSocket.GetTurnServerInfo(token);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="key"></param>
        /// <param name="name"></param>
        public void SetProfileName(byte[] key, string name)
        {
            if (name == null) name = "";
            string ciphertextName = Base64.EncodeBytesWithoutPadding(new ProfileCipher(key).EncryptName(Encoding.Unicode.GetBytes(name), ProfileCipher.NAME_PADDED_LENGTH));
            PushServiceSocket.SetProfileName(ciphertextName);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="key"></param>
        /// <param name="avatar"></param>
        public void SetProfileAvatar(byte[] key, StreamDetails avatar)
        {
            ProfileAvatarData profileAvatarData = null;
            if (avatar != null)
            {
                profileAvatarData = new ProfileAvatarData(avatar.InputStream, avatar.Length, avatar.ContentType, new ProfileCipherOutputStreamFactory(key));
            }
            PushServiceSocket.SetProfileAvatar(profileAvatarData);
        }

        /// <summary>
        /// TODO
        /// </summary>
        /// <param name="soTimeoutMillis"></param>
        public void SetSoTimeoutMillis(long soTimeoutMillis)
        {
            this.PushServiceSocket.SetSoTimeoutMillis(soTimeoutMillis);
        }

        /// <summary>
        /// TODO
        /// </summary>
        public void CancelInFlightRequests()
        {
            this.PushServiceSocket.CancelInFlightRequests();
        }

        private string CreateDirectoryServerToken(string e164number, bool urlSafe)
        {
            try
            {
                byte[] token = Util.Trim(Hash.Sha1(Encoding.UTF8.GetBytes(e164number)), 10);
                string encoded = Base64.EncodeBytesWithoutPadding(token);

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


#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public class SignalServiceProvisionMessage
    {
        public IdentityKeyPair Identity { get; internal set; }
        public string Number { get; internal set; }
        public string Code { get; internal set; }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
