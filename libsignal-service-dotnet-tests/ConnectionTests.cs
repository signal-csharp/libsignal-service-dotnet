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
        public static SignalCdnUrl[] CdnUrls = new SignalCdnUrl[] { new SignalCdnUrl("https://cdn.signal.org"), new SignalCdnUrl("https://cdn2.signal.org") };
        public static SignalContactDiscoveryUrl[] ContactDiscoveryUrls = new SignalContactDiscoveryUrl[] { new SignalContactDiscoveryUrl("https://api.directory.signal.org") };

        public static SignalServiceUrl[] ServiceStagingUrls = new SignalServiceUrl[] { new SignalServiceUrl("https://textsecure-service-staging.whispersystems.org") };
        public static SignalCdnUrl[] CdnStagingUrls = new SignalCdnUrl[] { new SignalCdnUrl("https://cdn-staging.signal.org"), new SignalCdnUrl("https://cdn2-staging.signal.org") };
        public static SignalContactDiscoveryUrl[] ContactDiscoveryStagingUrls = new SignalContactDiscoveryUrl[] { new SignalContactDiscoveryUrl("https://api-staging.directory.signal.org") };

        public static SignalServiceConfiguration ServiceConfiguration = new SignalServiceConfiguration(ServiceUrls, CdnUrls, ContactDiscoveryUrls);
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
            foreach (var url in ServiceUrls)
            {
                await httpClient.GetAsync(url.Url);
            }

            foreach (var url in CdnUrls)
            {
                await httpClient.GetAsync(url.Url);
            }

            foreach (var url in ContactDiscoveryUrls)
            {
                await httpClient.GetAsync(url.Url);
            }

            foreach (var url in ServiceStagingUrls)
            {
                await httpClient.GetAsync(url.Url);
            }

            foreach (var url in CdnStagingUrls)
            {
                await httpClient.GetAsync(url.Url);
            }

            foreach (var url in ContactDiscoveryStagingUrls)
            {
                await httpClient.GetAsync(url.Url);
            }
        }
    }
}
