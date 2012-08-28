using System;
using SHHH.Cryptography.Cryptographers;

namespace SHHH.Cryptography
{
    public class Cryptographer
    {
        private static Cryptographer _instance;
        private readonly static object _synLock = new object();

        protected Cryptographer()
        {
            InternalCryptographer = new DefaultCryptographer();
        }

        private ICryptographer InternalCryptographer { get; set; }

        public string Encrypt(string salt, string toEncrypt)
        {
            return InternalCryptographer.Encrypt(salt, toEncrypt);
        }
        public string Decrypt(string salt, string toDecrypt)
        {
            return InternalCryptographer.Decrypt(salt, toDecrypt);
        }
        public static Cryptographer Current
        {
            get
            {
                lock (_synLock)
                {
                    if (_instance == null)
                        _instance = new Cryptographer();
                }
                return _instance;
            }
        }

        public void SetCryptographer(ICryptographer cryptographer)
        {
            if (cryptographer == null) throw new ArgumentNullException("cryptographer");

            InternalCryptographer = cryptographer;
        }

    }
}
