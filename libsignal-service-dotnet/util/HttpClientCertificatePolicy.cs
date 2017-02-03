using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.util
{
    public enum HttpClientCertificatePolicy
    {
        /// <summary>
        /// Strict represents the default SSL behavior provided by HttpClient (i.e. make sure the certificate authority is trusted, certificate is not expired, etc)
        /// </summary>
        Strict,
        /// <summary>
        /// In Development mode, the certificate validation is relaxed. Self signed certificates may be used.
        /// </summary>
        DevelopmentMode
    }

    public static class HttpClientCertificatePolicyState
    {
        /// <summary>
        /// Used throughout the library to control the strictness of SSL validation for production / non-production scenarios.
        /// </summary>
        public static HttpClientCertificatePolicy Policy = HttpClientCertificatePolicy.Strict;
    }
}
