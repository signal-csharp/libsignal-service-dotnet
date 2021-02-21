using libsignalservice.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace libsignal_service_dotnet_tests.util
{
    [TestClass]
    public class PhoneNumberFormatterTests
    {
        private const string LOCAL_NUMBER_US = "+15555555555";
        private const string NUMBER_CH = "+41446681800";
        private const string NUMBER_UK = "+442079460018";
        private const string NUMBER_DE = "+4930123456";
        private const string NUMBER_MOBILE_DE = "+49171123456";
        private const string COUNTRY_CODE_CH = "41";
        private const string COUNTRY_CODE_UK = "44";
        private const string COUNTRY_CODE_DE = "49";

        [TestMethod]
        public void TestIsValidNumber()
        {
            Assert.IsTrue(PhoneNumberFormatter.IsValidNumber("+5521912345678", "55"));
            Assert.IsTrue(PhoneNumberFormatter.IsValidNumber("+552112345678", "55"));
            Assert.IsTrue(PhoneNumberFormatter.IsValidNumber("+16105880522", "1"));

            Assert.IsFalse(PhoneNumberFormatter.IsValidNumber("+5512345678", "55"));
            Assert.IsFalse(PhoneNumberFormatter.IsValidNumber("+161058805220", "1"));
            Assert.IsFalse(PhoneNumberFormatter.IsValidNumber("+1610588052", "1"));
            Assert.IsFalse(PhoneNumberFormatter.IsValidNumber("+15880522", "1"));
        }

        [TestMethod]
        public void TestFormatNumber()
        {
            Assert.AreEqual(LOCAL_NUMBER_US, PhoneNumberFormatter.FormatNumber("(555) 555-5555", LOCAL_NUMBER_US));
            Assert.AreEqual(LOCAL_NUMBER_US, PhoneNumberFormatter.FormatNumber("555-5555", LOCAL_NUMBER_US));
            Assert.AreNotEqual(LOCAL_NUMBER_US, PhoneNumberFormatter.FormatNumber("(123) 555-5555", LOCAL_NUMBER_US));
        }

        [TestMethod]
        public void TestFormatNumberEmail()
        {
            try
            {
                PhoneNumberFormatter.FormatNumber("person@domain.com", LOCAL_NUMBER_US);
                Assert.Fail("should have thrown on email");
            }
            catch (InvalidNumberException)
            {
                // success
            }
        }

        [TestMethod]
        public void TestFormatNumberE164()
        {
            Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_UK, "(020) 7946 0018"));
            //Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_UK, "044 20 7946 0018"));
            Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_UK, "+442079460018"));
            Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_UK, "+4402079460018"));

            Assert.AreEqual(NUMBER_CH, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_CH, "+41 44 668 18 00"));
            Assert.AreEqual(NUMBER_CH, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_CH, "+41 (044) 6681800"));

            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0049 030 123456"));
            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0049 (0)30123456"));
            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0049((0)30)123456"));
            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "+49 (0) 30  1 2  3 45 6 "));
            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "030 123456"));

            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0171123456"));
            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0171/123456"));
            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "+490171/123456"));
            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "00490171/123456"));
            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatE164(COUNTRY_CODE_DE, "0049171/123456"));
        }

        [TestMethod]
        public void TestFormatRemoteNumberE164()
        {
            Assert.AreEqual(LOCAL_NUMBER_US, PhoneNumberFormatter.FormatNumber(LOCAL_NUMBER_US, NUMBER_UK));
            Assert.AreEqual(LOCAL_NUMBER_US, PhoneNumberFormatter.FormatNumber(LOCAL_NUMBER_US, LOCAL_NUMBER_US));

            Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatNumber(NUMBER_UK, NUMBER_UK));
            Assert.AreEqual(NUMBER_CH, PhoneNumberFormatter.FormatNumber(NUMBER_CH, NUMBER_CH));
            Assert.AreEqual(NUMBER_DE, PhoneNumberFormatter.FormatNumber(NUMBER_DE, NUMBER_DE));
            Assert.AreEqual(NUMBER_MOBILE_DE, PhoneNumberFormatter.FormatNumber(NUMBER_MOBILE_DE, NUMBER_DE));

            Assert.AreEqual(NUMBER_UK, PhoneNumberFormatter.FormatNumber("+4402079460018", LOCAL_NUMBER_US));
        }
    }
}
