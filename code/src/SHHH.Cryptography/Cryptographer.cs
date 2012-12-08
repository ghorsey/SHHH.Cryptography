// <copyright file="Cryptographer.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography
{
    using System;
    using SHHH.Cryptography.Cryptographers;

    /// <summary>
    /// The object used to encrypt and decrypt strings.
    /// </summary>
    public class Cryptographer
    {
        /// <summary>
        /// The static object used to lock the shared data
        /// </summary>
        private static readonly object SynLock = new object();

        /// <summary>
        /// The _instance
        /// </summary>
        private static Cryptographer instance;

        /// <summary>
        /// Initializes a new instance of the <see cref="Cryptographer" /> class.
        /// </summary>
        protected Cryptographer()
        {
            this.InternalCryptographer = new DefaultCryptographer();
        }

        /// <summary>
        /// Gets the current.
        /// </summary>
        /// <value>
        /// The current.
        /// </value>
        public static Cryptographer Current
        {
            get
            {
                lock (SynLock)
                {
                    if (instance == null)
                    {
                        instance = new Cryptographer();
                    }
                }

                return instance;
            }
        }

        /// <summary>
        /// Gets or sets the internal cryptographer.
        /// </summary>
        /// <value>
        /// The internal cryptographer.
        /// </value>
        private ICryptographer InternalCryptographer { get; set; }

        /// <summary>
        /// Encrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <returns>The encrypted <see cref="System.String"/>.</returns>
        public string Encrypt(string salt, string toEncrypt)
        {
            return this.InternalCryptographer.Encrypt(salt, toEncrypt);
        }

        /// <summary>
        /// Decrypts the specified salt.
        /// </summary>
        /// <param name="salt">The salt.</param>
        /// <param name="toDecrypt">To decrypt.</param>
        /// <returns>The decrypted <see cref="System.String"/></returns>
        public string Decrypt(string salt, string toDecrypt)
        {
            return this.InternalCryptographer.Decrypt(salt, toDecrypt);
        }

        /// <summary>
        /// Sets the cryptographer.
        /// </summary>
        /// <param name="cryptographer">The cryptographer.</param>
        /// <exception cref="System.ArgumentNullException">The cryptographer parameter cannot be null</exception>
        public void SetCryptographer(ICryptographer cryptographer)
        {
            if (cryptographer == null)
            {
                throw new ArgumentNullException("cryptographer");
            }

            this.InternalCryptographer = cryptographer;
        }
    }
}
