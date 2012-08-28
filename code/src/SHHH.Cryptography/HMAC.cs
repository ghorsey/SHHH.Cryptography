using System;
using System.Security.Cryptography;
using System.Text;

namespace SHHH.Cryptography
{
    public class HMAC
    {
        public enum HMACResult { OK, Expired, Invalid };

        private byte[] Key { get; set; }

        public HMAC(byte[] key)
        {
            Key = key;
        }

        public string ComputeHash(string salt, string data, DateTime expiry)
        {
            HMACSHA1 alg = new HMACSHA1(Key);

            string input = expiry.Ticks + salt + data;

            byte[] hash = alg.ComputeHash(Encoding.UTF8.GetBytes(input));

            byte[] result = new byte[8 + hash.Length];
            hash.CopyTo(result, 8);
            BitConverter.GetBytes(expiry.Ticks).CopyTo(result, 0);
            return Swap(Convert.ToBase64String(result), "+=/", "-_,");
        }

        public HMACResult VerifyHash(string salt, string data, string hash)
        {
            byte[] bytes = Convert.FromBase64String(Swap(hash, "-_,", "+=/"));
            DateTime claimExpiry = new DateTime(BitConverter.ToInt64(bytes, 0));

            if (claimExpiry < DateTime.Now)
                return HMACResult.Expired;
            else if (hash == ComputeHash(salt, data, claimExpiry))
                return HMACResult.OK;
            else return HMACResult.Invalid;
        }

        private static string Swap(string str, string input, string output)
        {
            for (int i = 0; i < input.Length; i++)
                str = str.Replace(input[i], output[i]);
            return str;
        }
    }
}
