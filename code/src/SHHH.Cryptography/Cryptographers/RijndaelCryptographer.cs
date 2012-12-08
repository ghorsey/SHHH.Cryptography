// <copyright file="RijndaelCryptographer.cs" company="SHHH Innovations LLC">
// Copyright SHHH Innovations LLC
// </copyright>

namespace SHHH.Cryptography.Cryptographers
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using SHHH.Cryptography.Globalization;

    /// <summary>
    /// A Rijndael Cryptographer, Passphrase can be set in the app setting key <c>"RijndaelSimple::PassPhrase"</c>, otherwise
    /// a default is used.
    /// And a 16 byte initialization vector can be set in the app setting key <c>"RijndaelSimple::16ByteInitVector"</c>, otherwise a
    /// default initialization vector is used.
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1650:ElementDocumentationMustBeSpelledCorrectly", Justification = "Reviewed.")]
    public class RijndaelCryptographer : ICryptographer
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="RijndaelCryptographer" /> class.
        /// </summary>
        /// <param name="passPhrase">The pass phrase.</param>
        /// <param name="initVector16Bytes">The 16 bytes initialization vector.</param>
        /// <exception cref="System.ArgumentException">The <c>passPhrase</c> and <c>initVector16Bytes</c>cannot be null or whitespace</exception>
        public RijndaelCryptographer(string passPhrase, string initVector16Bytes)
        {
            if (string.IsNullOrWhiteSpace(passPhrase))
            {
                throw new ArgumentException(Exceptions.MissingEmptyPassPhrase, "passPhrase");
            }

            if (string.IsNullOrWhiteSpace(initVector16Bytes) || initVector16Bytes.Length != 16)
            {
                throw new ArgumentException(Exceptions.InvalidInitVector, "initVector16Bytes");
            }

            this.InitVector = initVector16Bytes;
            this.PassPhrase = passPhrase;
        }

        /// <summary>
        /// Gets or sets the pass phrase used to encrypt the data. A passphrase can be set in the AppSetting key "RijndaelSimple::PassPhrase".
        /// </summary>
        /// <value>The pass phrase.</value>
        private string PassPhrase { get; set; }

        /// <summary>
        /// Gets or sets the initialization vector, a 16 byte string from the AppSetting key <c>"RijndaelSimple::16ByteInitVector"</c>.
        /// </summary>
        /// <value>The initialization vector.</value>
        private string InitVector { get; set; }

        #region SampleCode
        /// <summary>
        /// Encrypts the specified to encrypt.
        /// </summary>
        /// <param name="toEncrypt">To encrypt.</param>
        /// <param name="passPhrase">The pass phrase.</param>
        /// <param name="saltValue">The salt value.</param>
        /// <param name="hashAlgorithm">The hash algorithm.</param>
        /// <param name="passwordIterations">The password iterations.</param>
        /// <param name="initVector">The init vector.</param>
        /// <param name="keySize">Size of the key.</param>
        /// <returns>The encrypted string</returns>
        public static string Encrypt(
            string toEncrypt, 
            string passPhrase, 
            string saltValue, 
            string hashAlgorithm,
            int passwordIterations, 
            string initVector, 
            int keySize)
        {
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

            // Convert our plaintext into a byte array.
            // Let us assume that plaintext contains UTF8-encoded characters.
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(toEncrypt);

            // First, we must create a password, from which the key will be derived.
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations.
            PasswordDeriveBytes password = new PasswordDeriveBytes(
                                                            passPhrase,
                                                            saltValueBytes,
                                                            hashAlgorithm,
                                                            passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes.
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption).
            CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);

            // Start encrypting.
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting.
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array.
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert encrypted data into a base64-encoded string.
            string cipherText = Convert.ToBase64String(cipherTextBytes);

            // Return encrypted string.
            return cipherText;
        }

        /// <summary>
        /// Decrypts specified <c>cipherText</c> using Rijndael symmetric key algorithm.
        /// </summary>
        /// <param name="cipherText">Base64-formatted <c>cipherText</c> value.</param>
        /// <param name="passPhrase">Passphrase from which a pseudo-random password will be derived. The
        /// derived password will be used to generate the encryption key.
        /// Passphrase can be any string. In this example we assume that this
        /// passphrase is an ASCII string.</param>
        /// <param name="saltValue">Salt value used along with passphrase to generate password. Salt can
        /// be any string. In this example we assume that salt is an ASCII string.</param>
        /// <param name="hashAlgorithm">Hash algorithm used to generate password. Allowed values are: "MD5" and
        /// "SHA1". SHA1 hashes are a bit slower, but more secure than MD5 hashes.</param>
        /// <param name="passwordIterations">Number of iterations used to generate password. One or two iterations
        /// should be enough.</param>
        /// <param name="initVector">Initialization vector (or IV). This value is required to encrypt the
        /// first block of plaintext data. For RijndaelManaged class IV must be
        /// exactly 16 ASCII characters long.</param>
        /// <param name="keySize">Size of encryption key in bits. Allowed values are: 128, 192, and 256.
        /// Longer keys are more secure than shorter keys.</param>
        /// <returns>
        /// Decrypted string value.
        /// </returns>
        /// <remarks>
        /// Most of the logic in this function is similar to the Encrypt
        /// logic. In order for decryption to work, all parameters of this function
        /// - except <c>cipherText</c> value - must match the corresponding parameters of
        /// the Encrypt function which was called to generate the
        /// cipher text.
        /// </remarks>
        public static string Decrypt(
            string cipherText,
            string passPhrase,
            string saltValue,
            string hashAlgorithm,
            int passwordIterations,
            string initVector,
            int keySize)
        {
            // Convert strings defining encryption key characteristics into byte
            // arrays. Let us assume that strings only contain ASCII codes.
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8
            // encoding.
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(initVector);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(saltValue);

            // Convert our ciphertext into a byte array.
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using
            // the specified hash algorithm. Password creation can be done in
            // several iterations.
            PasswordDeriveBytes password = new PasswordDeriveBytes(
                                                            passPhrase,
                                                            saltValueBytes,
                                                            hashAlgorithm,
                                                            passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;

            // Generate decryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes.
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            // Define cryptographic stream (always use Read mode for encryption).
            CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);

            // Since at this point we don't know what the size of decrypted data
            // will be, allocate the buffer long enough to hold ciphertext;
            // plaintext is never longer than ciphertext.
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            // Start decrypting.
            int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded.
            string plainText = Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);

            // Return decrypted string.   
            return plainText;
        }
        #endregion

        #region ICryptographer Members

        /// <summary>
        /// Encrypts the to encrypt string with the salt specified.
        /// </summary>
        /// <param name="salt">The salt to add to the encrypted data.</param>
        /// <param name="toEncrypt">To data to encrypt.</param>
        /// <returns>
        /// The encrypted string
        /// </returns>
        public string Encrypt(string salt, string toEncrypt)
        {
            if (toEncrypt == null)
            {
                return null;
            }

            return Encrypt(toEncrypt, this.PassPhrase, salt, "SHA1", 2, this.InitVector, 256);
        }

        /// <summary>
        /// Decrypts the to decrypt with the specified salt.
        /// </summary>
        /// <param name="salt">The salt to be removed from the encrypted data.</param>
        /// <param name="toDecrypt">To data to decrypt.</param>
        /// <returns>
        /// The decrypted string
        /// </returns>
        public string Decrypt(string salt, string toDecrypt)
        {
            if (toDecrypt == null)
            {
                return null;
            }

            return Decrypt(toDecrypt, this.PassPhrase, salt, "SHA1", 2, this.InitVector, 256);
        }

        #endregion
    }
}
