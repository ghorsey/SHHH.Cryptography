// <copyright file="CrypographyExtensions.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>
namespace SHHH.Cryptography
{
    /// <summary>
    /// Collection of extension methods for working with the cryptography library
    /// </summary>
    public static class CrypographyExtensions
    {
        /// <summary>
        /// Masks the string with the <c>maskChar</c> character.
        /// </summary>
        /// <example>
        /// <c>MaskLeft("4111111111111111", "*", 4) = "***********1111"</c>
        /// </example>
        /// <param name="toMask">The string to mask.</param>
        /// <param name="maskChar">The mask character.</param>
        /// <param name="showLast">Show last <see cref="System.Int"/> characters.</param>
        /// <returns>The masked <see cref="System.String"/></returns>
        public static string MaskLeft(this string toMask, char maskChar, int showLast)
        {
            if (toMask.Length <= showLast)
            {
                return toMask;
            }

            string result = CreateMask(toMask, maskChar, showLast);

            return string.Concat(result, toMask.Substring(toMask.Length - showLast));
        }

        /// <summary>
        /// Masks the string with the <c>maskChar</c>, showing only the first <c>showFirst</c> characters
        /// </summary>
        /// <example>
        /// <c>MaskRight("4111111111111111", "*", 4) = "4111************"</c>
        /// </example>
        /// <param name="toMask">To mask.</param>
        /// <param name="maskChar">The mask character.</param>
        /// <param name="showFirst">The show first x characters.</param>
        /// <returns>The masked <see cref="System.String"/></returns>
        public static string MaskRight(this string toMask, char maskChar, int showFirst)
        {
            if (toMask.Length <= showFirst)
            {
                return toMask;
            }

            string mask = CreateMask(toMask, maskChar, showFirst);

            return string.Concat(toMask.Substring(0, showFirst), mask);
        }

        /// <summary>
        /// Decrypts the specified to decrypt.
        /// </summary>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <returns>
        /// The decrypted data
        /// </returns>
        public static string Decrypt(this string toDecrypt)
        {
            return Decrypt(toDecrypt, string.Empty);
        }

        /// <summary>
        /// Decrypts the specified to decrypt.
        /// </summary>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>
        /// The decrypted data
        /// </returns>
        public static string Decrypt(this string toDecrypt, string salt)
        {
            return Cryptographer.Current.Decrypt(salt, toDecrypt);
        }

        /// <summary>
        /// Encrypts the specified to encrypt.
        /// </summary>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <returns>
        /// The data encrypted
        /// </returns>
        public static string Encrypt(this string toEncrypt)
        {
            return Encrypt(toEncrypt, string.Empty);
        }

        /// <summary>
        /// Encrypts the specified to encrypt.
        /// </summary>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>
        /// The data decrypted
        /// </returns>
        public static string Encrypt(this string toEncrypt, string salt)
        {
            return Cryptographer.Current.Encrypt(salt, toEncrypt);
        }

        /// <summary>
        /// Creates the mask.
        /// </summary>
        /// <param name="toMask">To mask.</param>
        /// <param name="maskChar">The mask char.</param>
        /// <param name="unmask">The unmask.</param>
        /// <returns>The masked <see cref="System.String"/></returns>
        private static string CreateMask(string toMask, char maskChar, int unmask)
        {
            return string.Empty.PadLeft(toMask.Length - unmask, maskChar);
        }
    }
}
