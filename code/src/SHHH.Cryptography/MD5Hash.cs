// <copyright file="MD5Hash.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography
{
    using System;
    using System.Security.Cryptography;

    /// <summary>
    /// A class used to compute a MD5 hash
    /// </summary>
    public static class MD5Hash
    {
        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>A MD5 has of the input string</returns>
        public static string ComputeHash(string input)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            byte[] inputArray = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hashedArray = md5.ComputeHash(inputArray);
            md5.Clear();
            return BitConverter.ToString(hashedArray).Replace("-", string.Empty).ToLowerInvariant();
        }
    }
}
