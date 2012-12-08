// <copyright file="DefaultCryptographer.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography.Cryptographers
{
    /// <summary>
    /// The default cryptographer does no encryption and just passes through string values
    /// </summary>
    public class DefaultCryptographer : ICryptographer
    {
        /// <summary>
        /// Encrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <returns>
        /// The encrypted string
        /// </returns>
        public string Encrypt(string salt, string toEncrypt)
        {
            return toEncrypt;
        }

        /// <summary>
        /// Decrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <returns>
        /// The decrypted string
        /// </returns>
        public string Decrypt(string salt, string toDecrypt)
        {
            return toDecrypt;
        }
    }
}