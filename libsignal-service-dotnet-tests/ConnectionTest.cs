using libsignalservice;
using libsignalservice.configuration;
using libsignalservice.push.exceptions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace libsignal_service_dotnet_tests
{
    [TestClass]
    public class ConnectionTest
    {
        public static SignalServiceUrl[] ServiceUrls = new SignalServiceUrl[] { new SignalServiceUrl("https://textsecure-service.whispersystems.org") };
        public static SignalServiceConfiguration ServiceConfiguration = new SignalServiceConfiguration(ServiceUrls, null, null);
        public static string UserAgent = "libsignal-service-dotnet-tests";

        [TestMethod]
        public async Task TestConnection()
        {
            var cancelSource = new CancellationTokenSource();
            var pushServiceSocket = new SignalServiceAccountManager(ServiceConfiguration, "A", "B", 1, UserAgent);
            try
            {
                var turn = await pushServiceSocket.GetTurnServerInfo(cancelSource.Token);
            }
            catch (AuthorizationFailedException) { }
        }
    }
}
