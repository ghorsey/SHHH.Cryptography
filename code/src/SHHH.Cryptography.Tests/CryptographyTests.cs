using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NUnit.Framework;
using SHHH.Cryptography.Cryptographers;

namespace SHHH.Cryptography.Tests
{
    [TestFixture]
    public class CryptographyTests
    {
        private const string DecodedString = "This is my string";
        private const string EncodedRinjndaelString = "Y73wEClZpRPyki1H6akbtxQ7q87SZZG3HwVjWY9UDqg=";
        private const string Salt = "my-salt";

        [Test]
        public void CanMasLeft()
        {
            Assert.AreEqual("*****6789", "123456789".MaskLeft('*', 4));
        }

        [Test]
        public void CanMasRight()
        {
            Assert.AreEqual("123^^^^^^", "123456789".MaskRight('^', 3));
        }


        [Test]
        public void DefaultDecrypterDoesNotChangeAnything()
        {

            Cryptographer.Current.SetCryptographer(new DefaultCryptographer());

            string result = Cryptographer.Current.Decrypt(Salt, DecodedString);

            Assert.AreEqual(DecodedString, result);
        }

        [Test]
        public void DefaultEncrypterDoesNotChangeAnything()
        {

            Cryptographer.Current.SetCryptographer(new DefaultCryptographer());

            string result = Cryptographer.Current.Encrypt(Salt, DecodedString);

            Assert.AreEqual(DecodedString, result);
        }

        [Test]
        public void RinjndaelCryptographyEncrypt()
        {
            Cryptographer.Current.SetCryptographer(new RijndaelCryptographer("passPhrase", "1234567890123456"));

            string result = Cryptographer.Current.Encrypt(Salt, DecodedString);

            Assert.AreEqual(EncodedRinjndaelString, result);
        }

        [Test]
        public void RinjndaelCryptographyDecrypt()
        {
            Cryptographer.Current.SetCryptographer(new RijndaelCryptographer("passPhrase", "1234567890123456"));

            string result = Cryptographer.Current.Decrypt(Salt, EncodedRinjndaelString);

            Assert.AreEqual(DecodedString, result);
        }
    }
}
