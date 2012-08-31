using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace SHHH.Cryptography
{
    public class MD5Hash
    {
        public static string ComputeHash(string input)
        {
            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
            byte[] inputArray = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hashedArray = md5.ComputeHash(inputArray);
            md5.Clear();
            return BitConverter.ToString(hashedArray).Replace("-", "").ToLowerInvariant();
        }
    }
}
