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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace libsignalservice.messages.multidevice
{
    public class ChunkedOutputStream
    {

        protected readonly Stream output;

        public ChunkedOutputStream(Stream output)
        {
            this.output = output;
        }

        protected void writeVarint32(int value)// throws IOException
        {
            /*while (true)
            {
                if ((value & ~0x7F) == 0)
                {
                    output.Write(value, 0);
                    return;
                }
                else
                {
                    output.Write((value & 0x7F) | 0x80);
                    value >>= 7;
                }
            }*/
            throw new NotImplementedException();
        }

        protected void writeStream(Stream input)// throws IOException
        {
            /*byte[] buffer = new byte[4096];
            int read;

            while ((read = input.read(buffer)) != -1) {
                output.write(buffer, 0, read);
            }

            input.close();*/
            throw new NotImplementedException();
        }

    }
}
