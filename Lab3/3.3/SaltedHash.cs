using System.Security.Cryptography;
using System.Text;

public class SaltedHash
{
    public byte[] Salt { get; }
    public byte[] Hash { get; }

    public SaltedHash(string password, int saltLength = 32)
    {
        Salt = new byte[saltLength];
        using var rnd = RandomNumberGenerator.Create();
        rnd.GetBytes(Salt);

        Hash = ComputeHash(password, Salt);
    }

    public SaltedHash(byte[] salt, byte[] hash)
    {
        Salt = salt;
        Hash = hash;
    }

    public static byte[] ComputeHash(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] combined = new byte[passwordBytes.Length + salt.Length];
        Buffer.BlockCopy(passwordBytes, 0, combined, 0, passwordBytes.Length);
        Buffer.BlockCopy(salt, 0, combined, passwordBytes.Length, salt.Length);

        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(combined);
    }

    public bool Verify(string password)
    {
        byte[] candidate = ComputeHash(password, Salt);
        return CryptographicOperations.FixedTimeEquals(candidate, Hash);
    }
}
