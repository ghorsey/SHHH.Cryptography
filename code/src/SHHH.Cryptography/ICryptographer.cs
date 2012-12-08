// <copyright file="ICryptographer.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography
{
    /// <summary>
    /// The interface with describes the methods which must be implemented by a concrete cryptographer
    /// </summary>
    public interface ICryptographer
    {
        /// <summary>
        /// Encrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <returns>The encrypted string</returns>
        string Encrypt(string salt, string toEncrypt);

        /// <summary>
        /// Decrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <returns>The decrypted string</returns>
        string Decrypt(string salt, string toDecrypt);
    }
}
