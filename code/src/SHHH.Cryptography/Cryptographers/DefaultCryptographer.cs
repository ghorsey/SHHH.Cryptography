using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SHHH.Cryptography.Cryptographers
{

    public class DefaultCryptographer : ICryptographer
    {
        #region ICryptographer Members
        public string Encrypt(string salt, string toEncrypt)
        {
            return toEncrypt;
        }

        public string Decrypt(string salt, string toDecrypt)
        {
            return toDecrypt;
        }

        #endregion
    }

}