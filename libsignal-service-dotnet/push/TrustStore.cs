using System.IO;

namespace libsignalservice.push
{
    /// <summary>
    /// A class that represents a (Java KeyStore) and its associated password.
    /// </summary>
    public interface TrustStore
    {
        public Stream GetKeyStoreInputStream();
        public string GetKeyStorePassword();
    }
}
