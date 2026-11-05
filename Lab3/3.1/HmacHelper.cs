using System.Security.Cryptography;
using System.Text;

public static class HmacHelper
{
    public static byte[] GenerateKey(int length)
    {
        var key = new byte[length];
        using var rnd = RandomNumberGenerator.Create();
        rnd.GetBytes(key);
        return key;
    }

    public static byte[] ComputeMd5(byte[] data, byte[] key)
    {
        using var hmac = new HMACMD5(key);
        return hmac.ComputeHash(data);
    }

    public static byte[] ComputeSha1(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA1(key);
        return hmac.ComputeHash(data);
    }

    public static byte[] ComputeSha256(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA256(key);
        return hmac.ComputeHash(data);
    }

    public static byte[] ComputeSha512(byte[] data, byte[] key)
    {
        using var hmac = new HMACSHA512(key);
        return hmac.ComputeHash(data);
    }

    public static bool Verify(string message, byte[] receivedHmac, byte[] key)
    {
        byte[] computed = ComputeSha256(Encoding.UTF8.GetBytes(message), key);
        return CryptographicOperations.FixedTimeEquals(computed, receivedHmac);
    }
}
