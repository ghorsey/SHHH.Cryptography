
namespace SHHH.Cryptography
{
    public static class CrypographyExtensions
    {
        public static string MaskLeft(this string toMask, char maskChar, int showLast)
        {
            if (toMask.Length <= showLast) return toMask;

            string result = CreateMask(toMask, maskChar, showLast);

            return string.Concat(result, toMask.Substring(toMask.Length - showLast));
        }

        public static string MaskRight(this string toMask, char maskChar, int showFirst)
        {
            if (toMask.Length <= showFirst) return toMask;
            
            string mask = CreateMask(toMask, maskChar, showFirst);

            return string.Concat(toMask.Substring(0, showFirst), mask);
        }

        private static string CreateMask(string toMask, char maskChar, int unmask)
        {
            return "".PadLeft(toMask.Length - unmask, maskChar);
        }

        /// <summary>
        /// Decrypts the specified to decrypt.
        /// </summary>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <returns>The decrypted data</returns>
        public static string Decrypt(this string toDecrypt)
        {
            return Decrypt(toDecrypt, string.Empty);
        }
        /// <summary>
        /// Decrypts the specified to decrypt.
        /// </summary>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>The decrypted data</returns>
        public static string Decrypt(this string toDecrypt, string salt)
        {
            return Cryptographer.Current.Decrypt(salt, toDecrypt);
        }

        /// <summary>
        /// Encrypts the specified to encrypt.
        /// </summary>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <returns>The data encrypted</returns>
        public static string Encrypt(this string toEncrypt)
        {
            return Encrypt(toEncrypt, string.Empty);
        }

        /// <summary>
        /// Encrypts the specified to encrypt.
        /// </summary>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <param name="salt">The salt.</param>
        /// <returns>The data decrypted</returns>
        public static string Encrypt(this string toEncrypt, string salt)
        {
            return Cryptographer.Current.Encrypt(salt, toEncrypt);
        }

    }
}
