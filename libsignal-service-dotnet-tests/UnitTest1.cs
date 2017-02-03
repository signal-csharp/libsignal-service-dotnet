using System;
using libsignalservice;
using libsignalservice.push;
using signal;
using libsignal.util;
using libsignal;
using libsignal.state;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests
{
    [TestClass]
    public class UnitTest1
    {
        private string URL = "https://textsecure-service.whispersystems.org";
        private TrustStore TRUST_STORE = new SignalServiceTrustStore();
        private string USERNAME = "+491628396072";
        private string PASSWORD = "suchrandom";
        private string USER_AGENT = "signal-cli";

        [TestMethod]
        public void TestMethod1()
        {
            Console.WriteLine("hello world");
            IdentityKeyPair identityKey = KeyHelper.generateIdentityKeyPair();
            IList<PreKeyRecord> oneTimePreKeys = KeyHelper.generatePreKeys(0, 100);
            PreKeyRecord lastResortKey = KeyHelper.generateLastResortPreKey();
            SignedPreKeyRecord signedPreKeyRecord = KeyHelper.generateSignedPreKey(identityKey, 42);

            SignalServiceUrl[] urls = new SignalServiceUrl[] {
                new SignalServiceUrl(this.URL, this.TRUST_STORE)
            };
            SignalServiceAccountManager accountManager = new SignalServiceAccountManager(urls, USERNAME, PASSWORD, USER_AGENT);
            try
            {
                accountManager.requestSmsVerificationCode().Wait();
            } catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
