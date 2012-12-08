// <copyright file="CryptographyTests.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography.Tests
{
    using System.Diagnostics.CodeAnalysis;
    using NUnit.Framework;
    using SHHH.Cryptography.Cryptographers;

    /// <summary>
    /// The Cryptography tests
    /// </summary>
    [TestFixture]
    public class CryptographyTests
    {
        /// <summary>
        /// The decoded string
        /// </summary>
        private const string DecodedString = "This is my string";

        /// <summary>
        /// The encoded rinjndael string
        /// </summary>
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1650:ElementDocumentationMustBeSpelledCorrectly", Justification = "Reviewed.")]
        private const string EncodedRinjndaelString = "Y73wEClZpRPyki1H6akbtxQ7q87SZZG3HwVjWY9UDqg=";

        /// <summary>
        /// The salt
        /// </summary>
        private const string Salt = "my-salt";

        /// <summary>
        /// Determines whether this instance can mask left.
        /// </summary>
        [Test]
        public void CanMaskLeft()
        {
            Assert.AreEqual("*****6789", "123456789".MaskLeft('*', 4));
        }

        /// <summary>
        /// Determines whether this instance can mask right.
        /// </summary>
        [Test]
        public void CanMaskRight()
        {
            Assert.AreEqual("123^^^^^^", "123456789".MaskRight('^', 3));
        }

        /// <summary>
        /// The default cryptographer does not change anything.
        /// </summary>
        [Test]
        public void DefaultDecrypterDoesNotChangeAnything()
        {
            Cryptographer.Current.SetCryptographer(new DefaultCryptographer());

            string result = Cryptographer.Current.Decrypt(Salt, DecodedString);

            Assert.AreEqual(DecodedString, result);
        }

        /// <summary>
        /// The default cryptographer does not change anything.
        /// </summary>
        [Test]
        public void DefaultEncrypterDoesNotChangeAnything()
        {
            Cryptographer.Current.SetCryptographer(new DefaultCryptographer());

            string result = Cryptographer.Current.Encrypt(Salt, DecodedString);

            Assert.AreEqual(DecodedString, result);
        }

        /// <summary>
        /// Rijndaels the cryptography encrypt.
        /// </summary>
        [Test]
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1650:ElementDocumentationMustBeSpelledCorrectly", Justification = "Reviewed.")]
        public void RijndaelCryptographyEncrypt()
        {
            Cryptographer.Current.SetCryptographer(new RijndaelCryptographer("passPhrase", "1234567890123456"));

            string result = Cryptographer.Current.Encrypt(Salt, DecodedString);

            Assert.AreEqual(EncodedRinjndaelString, result);
        }

        /// <summary>
        /// Rinjndaels the cryptography decrypt.
        /// </summary>
        [Test]
        [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1650:ElementDocumentationMustBeSpelledCorrectly", Justification = "Reviewed.")]
        public void RinjndaelCryptographyDecrypt()
        {
            Cryptographer.Current.SetCryptographer(new RijndaelCryptographer("passPhrase", "1234567890123456"));

            string result = Cryptographer.Current.Decrypt(Salt, EncodedRinjndaelString);

            Assert.AreEqual(DecodedString, result);
        }
    }
}
