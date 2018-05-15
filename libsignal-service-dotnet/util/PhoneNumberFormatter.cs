using PhoneNumbers;
using System;
using System.Text.RegularExpressions;

namespace CustomExtensions
{
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
    public static class StringExtension
    {
        public static string ReplaceAll(this string str, string regex, string replacement)
        {
            return Regex.Replace(str, regex, replacement);
        }
    }
}

namespace libsignalservice.util
{
    using CustomExtensions;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Phone number formats are a pain.
    /// </summary>
    public class PhoneNumberFormatter
    {
        private static readonly ILogger Logger = LibsignalLogging.CreateLogger<PhoneNumberFormatter>();
        public static bool IsValidNumber(string number)
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

        private static string ImpreciseFormatNumber(string number, string localNumber)
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

        public static string FormatNumberInternational(string number)
        {
            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                PhoneNumber parsedNumber = util.Parse(number, null);
                return util.Format(parsedNumber, PhoneNumberFormat.INTERNATIONAL);
            }
            catch (NumberParseException e)
            {
                Logger.LogError("FormatNumberInternational() failed: {0}\n{1}", e.Message, e.StackTrace);
                return number;
            }
        }

        public static string FormatNumber(string number, string localNumber) //throws InvalidNumberException
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
                Logger.LogError("FormatNumber() failed: {0}\n{1}", e.Message, e.StackTrace);
                return ImpreciseFormatNumber(number, localNumber);
            }
        }

        public static string GetRegionDisplayName(string regionCode)
        {
            return (regionCode == null || regionCode.Equals("ZZ") || regionCode.Equals(PhoneNumberUtil.RegionCodeForNonGeoEntity))
                ? "Unknown country" : new Locale("", regionCode).GetDisplayCountry("en");
        }

        public static string FormatE164(string countryCode, string number)
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
            catch (Exception e)
            {
                Logger.LogError("FormatNumber() failed: {0}\n{1}", e.Message, e.StackTrace);
            }

            return "+" +
                countryCode.ReplaceAll("[^0-9]", "").ReplaceAll("^0*", "") +
                number.ReplaceAll("[^0-9]", "");
        }

        public static string GetInternationalFormatFromE164(string e164number)
        {
            try
            {
                PhoneNumberUtil util = PhoneNumberUtil.GetInstance();
                PhoneNumber parsedNumber = util.Parse(e164number, null);
                return util.Format(parsedNumber, PhoneNumberFormat.INTERNATIONAL);
            }
            catch (NumberParseException e)
            {
                Logger.LogError("GetInternationalFormatFromE164() failed: {0}\n{1}", e.Message, e.StackTrace);
                return e164number;
            }
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
