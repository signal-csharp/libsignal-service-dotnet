using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using libsignalservice;
using libsignalservice.configuration;
using libsignalservice.push.exceptions;
using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests
{
    [TestClass]
    public class ConnectionTests
    {
        public static SignalServiceUrl[] ServiceUrls = new SignalServiceUrl[] { new SignalServiceUrl("https://textsecure-service.whispersystems.org") };
        public static SignalContactDiscoveryUrl[] ContactDiscoveryUrls = new SignalContactDiscoveryUrl[] { new SignalContactDiscoveryUrl("https://api.directory.signal.org") };
        public static SignalServiceConfiguration ServiceConfiguration = new SignalServiceConfiguration(ServiceUrls, null, ContactDiscoveryUrls);
        public static string UserAgent = "libsignal-service-dotnet-tests";

        [TestMethod]
        public async Task TestConnection()
        {
            var cancelSource = new CancellationTokenSource();
            var pushServiceSocket = new SignalServiceAccountManager(ServiceConfiguration, "A", "B", 1, UserAgent, Util.CreateHttpClient());
            try
            {
                var turn = await pushServiceSocket.GetTurnServerInfo(cancelSource.Token);
            }
            catch (AuthorizationFailedException) { }
        }

        [TestMethod]
        public async Task TestSignalConnections()
        {
            using HttpClient httpClient = Util.CreateHttpClient();
            await httpClient.GetAsync(ServiceUrls[0].Url);
            await httpClient.GetAsync(ContactDiscoveryUrls[0].Url);
        }
    }
}
