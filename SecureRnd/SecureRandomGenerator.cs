using System.Security.Cryptography;

namespace SecureRnd
{
    public static class SecureRandomGenerator
    {
        public static byte[] GenerateRndBytes(int length)
        {
            var bytes = new byte[length];
            using var rnd = RandomNumberGenerator.Create();
            rnd.GetBytes(bytes);
            return bytes;
        }
    }
}