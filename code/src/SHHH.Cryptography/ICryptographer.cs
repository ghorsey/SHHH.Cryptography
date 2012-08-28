
namespace SHHH.Cryptography
{
    public interface ICryptographer
    {
        string Encrypt(string salt, string toEncrypt);
        string Decrypt(string salt, string toDecrypt);
    }
}
