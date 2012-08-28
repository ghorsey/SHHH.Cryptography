using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SHHH.Cryptography
{
    public interface ICryptographer
    {
        string Encrypt(string salt, string toEncrypt);
        string Decrypt(string salt, string toDecrypt);
    }
}
