// <copyright file="HMAC.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>
namespace SHHH.Cryptography
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Performs HMAC hashing
    /// </summary>
    public class HMAC
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HMAC" /> class.
        /// </summary>
        /// <param name="key">The key.</param>
        public HMAC(byte[] key)
        {
            this.Key = key;
        }

        /// <summary>
        /// The possible HMAC results of checking against a hashed value
        /// </summary>
        public enum HMACResult
        {
            /// <summary>
            /// The result passed validation
            /// </summary>
            OK,

            /// <summary>
            /// An expired result
            /// </summary>
            Expired,

            /// <summary>
            /// An invalid result
            /// </summary>
            Invalid 
        }

        /// <summary>
        /// Gets or sets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        private byte[] Key { get; set; }

        /// <summary>
        /// Computes the hash.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="data">The data.</param>
        /// <param name="expiry">The expiry.</param>
        /// <returns>The computed hash as a <see cref="System.String"/></returns>
        public string ComputeHash(string salt, string data, DateTime expiry)
        {
            HMACSHA1 alg = new HMACSHA1(this.Key);

            string input = expiry.Ticks + salt + data;

            byte[] hash = alg.ComputeHash(Encoding.UTF8.GetBytes(input));

            byte[] result = new byte[8 + hash.Length];
            hash.CopyTo(result, 8);
            BitConverter.GetBytes(expiry.Ticks).CopyTo(result, 0);
            return Swap(Convert.ToBase64String(result), "+=/", "-_,");
        }

        /// <summary>
        /// Verifies the hash.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="data">The data.</param>
        /// <param name="hash">The hash.</param>
        /// <returns><see cref="HMACResult"/></returns>
        public HMACResult VerifyHash(string salt, string data, string hash)
        {
            byte[] bytes = Convert.FromBase64String(Swap(hash, "-_,", "+=/"));
            DateTime claimExpiry = new DateTime(BitConverter.ToInt64(bytes, 0));

            if (claimExpiry < DateTime.Now)
            {
                return HMACResult.Expired;
            }
            else if (hash == this.ComputeHash(salt, data, claimExpiry))
            {
                return HMACResult.OK;
            }
            else
            {
                return HMACResult.Invalid;
            }
        }

        /// <summary>
        /// Swaps the specified STR.
        /// </summary>
        /// <param name="str">The STR.</param>
        /// <param name="input">The input.</param>
        /// <param name="output">The output.</param>
        /// <returns>The swapped value</returns>
        private static string Swap(string str, string input, string output)
        {
            for (int i = 0; i < input.Length; i++)
            {
                str = str.Replace(input[i], output[i]);
            }

            return str;
        }
    }
}
