/** 
 * Copyright (C) 2015 smndtrl
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace libsignalservice.push
{
    public class PushAttachmentData
    {

        private readonly String contentType;
        private readonly Stream data;
        private readonly ulong dataSize;
        private readonly byte[] key;
        
        public PushAttachmentData(String contentType, Stream data, ulong dataSize, byte[] key)
        {
            this.contentType = contentType;
            this.data = data;
            this.dataSize = dataSize;
            this.key = key;
        }

        public String getContentType()
        {
            return contentType;
        }

        public Stream getData()
        {
            return data;
        }

        public ulong getDataSize()
        {
            return dataSize;
        }

        public byte[] getKey()
        {
            return key;
        }
    }
}
