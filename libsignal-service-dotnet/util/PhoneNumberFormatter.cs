using System;
using System.Text.RegularExpressions;
using PhoneNumbers;

namespace CustomExtensions
{
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

        private const string COUNTRY_CODE_BR = "55";
        private const string COUNTRY_CODE_US = "1";

        public static bool IsValidNumber(string e164Number, string countryCode)
        {
            if (!PhoneNumberUtil.GetInstance().IsPossibleNumber(e164Number, countryCode))
            {
                Logger.LogError("Failed IsPossibleNumber()");
                return false;
            }

            if (COUNTRY_CODE_US == countryCode && !new Regex("^\\+1[0-9]{10}$").Match(e164Number).Success)
            {
                Logger.LogError("Failed US number format check");
                return false;
            }

            if (COUNTRY_CODE_BR == countryCode && !new Regex("^\\+55[0-9]{2}9?[0-9]{8}$").Match(e164Number).Success)
            {
                Logger.LogError("Failed Brazil number format check");
                return false;
            }

            return (new Regex("^\\+[1-9][0-9]{6,14}$").Match(e164Number)).Success;
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
}
