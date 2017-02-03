/** 
 * Copyright (C) 2015-2017 smndtrl, golf1052
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

using PhoneNumbers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;


namespace CustomExtensions {
    public static class StringExtension
    {
        public static string ReplaceAll(this string str, string regex, string replacement)
        {

            return Regex.Replace(str, regex, replacement) ;
        }
    }
}
namespace libsignalservice.util
{
    using CustomExtensions;

    /// <summary>
    /// Phone number formats are a pain.
    /// </summary>
    public class PhoneNumberFormatter
    {

        public static bool isValidNumber(string number)
        {
            return (new Regex("^\\+[0-9]{10,}").Match(number)).Success ||
                (new Regex("^\\+685[0-9]{5}").Match(number)).Success ||
                (new Regex("^\\+376[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+299[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+597[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+298[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+240[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+687[0-9]{6}").Match(number)).Success ||
                (new Regex("^\\+689[0-9]{6}").Match(number)).Success;
        }

        private static string impreciseFormatNumber(string number, string localNumber)
        //throws InvalidNumberException
        {
            number = number.ReplaceAll("[^0-9+]", "");

            if (number[0] == '+')
                return number;

            if (localNumber[0] == '+')
                localNumber = localNumber.Substring(1);

            if (localNumber.Length == number.Length || number.Length > localNumber.Length)
                return "+" + number;

            int difference = localNumber.Length - number.Length;

            return "+" + localNumber.Substring(0, difference) + number;
        }

        public static string formatNumberInternational(string number)
        {
            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                PhoneNumber parsedNumber = util.Parse(number, null);
                return util.Format(parsedNumber, PhoneNumberFormat.INTERNATIONAL);
            }
            catch (NumberParseException e)
            {
                //Log.w(TAG, e);
                return number;
            }
        }

        public static string formatNumber(string number, string localNumber) //throws InvalidNumberException
        {
            if (number == null)
            {
                throw new InvalidNumberException("Null string passed as number.");
            }

            if (number.Contains("@"))
            {
                throw new InvalidNumberException("Possible attempt to use email address.");
            }

            number = number.ReplaceAll("[^0-9+]", "");

            if (number.Length == 0)
            {
                throw new InvalidNumberException("No valid characters found.");
            }

            //if (number[0] == '+')
            //    return number;

            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                PhoneNumber localNumberObject = util.Parse(localNumber, null);

                string localCountryCode = util.GetRegionCodeForNumber(localNumberObject);
                //Log.w(TAG, "Got local CC: " + localCountryCode);

                PhoneNumber numberObject = util.Parse(number, localCountryCode);
                return util.Format(numberObject, PhoneNumberFormat.E164);
            }
            catch (NumberParseException e)
            {
                //Log.w(TAG, e);
                return impreciseFormatNumber(number, localNumber);
            }
        }

        public static string getRegionDisplayName(string regionCode)
        {
            return (regionCode == null || regionCode.Equals("ZZ") || regionCode.Equals(PhoneNumberUtil.REGION_CODE_FOR_NON_GEO_ENTITY))
                ? "Unknown country" : "TODO COUNTRY NAM";
        }

        public static string formatE164(string countryCode, string number)
        {
            if (countryCode == string.Empty || number == string.Empty) return string.Empty;
            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                int parsedCountryCode = Convert.ToInt32(countryCode);
                PhoneNumber parsedNumber = util.Parse(number,
                                                      util.GetRegionCodeForCountryCode(parsedCountryCode));

                return util.Format(parsedNumber, PhoneNumberFormat.E164);
            }
            catch (NumberParseException npe) {
                return string.Empty;
            } catch (Exception npe)
            {
                return string.Empty;
            }

            return "+" +
                countryCode.ReplaceAll("[^0-9]", "").ReplaceAll("^0*", "") +
                number.ReplaceAll("[^0-9]", "");
            }

  public static string getInternationalFormatFromE164(string e164number)
        {
            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                PhoneNumber parsedNumber = util.Parse(e164number, null);
                return util.Format(parsedNumber, PhoneNumberFormat.INTERNATIONAL);
            }
            catch (NumberParseException e)
            {
                //Log.w(TAG, e);
                return e164number;
            }
        }

    }
}
