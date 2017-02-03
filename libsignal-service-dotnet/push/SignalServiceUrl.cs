/** 
* Copyright (C) 2017 golf1052
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using Strilanc.Value;

namespace libsignalservice.push
{
    public class SignalServiceUrl
    {
        private readonly May<string> hostHeader;
        private readonly string url;
        private TrustStore trustStore;

        public SignalServiceUrl(string url, TrustStore trustStore)
            : this(url, null, trustStore)
        {
        }

        public SignalServiceUrl(string url, string hostHeader, TrustStore trustStore)
        {
            this.url = url;
            this.hostHeader = hostHeader == null ? May.NoValue : new May<string>(hostHeader);
            this.trustStore = trustStore;
        }

        public May<string> getHostHeader()
        {
            return hostHeader;
        }

        public string getUrl()
        {
            return url;
        }

        public TrustStore getTrustStore()
        {
            return trustStore;
        }

        //public May<ConnectionSpec> getConnectionSpec()
        //{
        //    return connectionSpec;
        //}
    }
}
