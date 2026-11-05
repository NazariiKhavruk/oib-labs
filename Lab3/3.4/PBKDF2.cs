using System.Security.Cryptography;
using System.Text;

// Реалізація PBKDF2 за RFC 2898 на основі HMAC.
// Вбудований Rfc2898DeriveBytes не підтримує MD5, тому HMAC і ітерації
// реалізовано вручну, щоб алгоритм був доступним для всіх п'яти варіантів.
public class PBKDF2
{
    public byte[] Salt { get; }

    private readonly HashAlgorithmName algorithm;

    // Створює новий обʼєкт із випадково згенерованою сіллю.
    public PBKDF2(HashAlgorithmName algorithm, int saltLength = 32)
    {
        this.algorithm = algorithm;
        Salt = RandomNumberGenerator.GetBytes(saltLength);
    }

    // Створює обʼєкт з уже наявною сіллю (для перевірки пароля).
    public PBKDF2(HashAlgorithmName algorithm, byte[] salt)
    {
        this.algorithm = algorithm;
        Salt = salt;
    }

    public byte[] ComputeHash(string password, int iterations, int keyLength = 32)
    {
        return Derive(Encoding.UTF8.GetBytes(password), Salt, iterations, algorithm, keyLength);
    }

    public static byte[] Derive(byte[] password, byte[] salt, int iterations,
                                HashAlgorithmName algorithm, int keyLength)
    {
        using HMAC hmac = CreateHmac(algorithm, password);

        int hLen = hmac.HashSize / 8;                 // довжина виходу PRF у байтах
        int blocks = (keyLength + hLen - 1) / hLen;   // скільки блоків потрібно
        byte[] result = new byte[keyLength];

        // вхід для першого кроку: сіль + номер блоку (4 байти, big-endian)
        byte[] blockInput = new byte[salt.Length + 4];
        Buffer.BlockCopy(salt, 0, blockInput, 0, salt.Length);

        for (int i = 1; i <= blocks; i++)
        {
            blockInput[salt.Length] = (byte)(i >> 24);
            blockInput[salt.Length + 1] = (byte)(i >> 16);
            blockInput[salt.Length + 2] = (byte)(i >> 8);
            blockInput[salt.Length + 3] = (byte)i;

            byte[] u = hmac.ComputeHash(blockInput);  // U1
            byte[] t = (byte[])u.Clone();             // T = U1

            for (int c = 1; c < iterations; c++)
            {
                u = hmac.ComputeHash(u);              // Uc = HMAC(P, U(c-1))
                for (int k = 0; k < t.Length; k++)
                    t[k] ^= u[k];                     // T = T XOR Uc
            }

            int offset = (i - 1) * hLen;
            int length = Math.Min(hLen, keyLength - offset);
            Buffer.BlockCopy(t, 0, result, offset, length);
        }

        return result;
    }

    private static HMAC CreateHmac(HashAlgorithmName algorithm, byte[] key)
    {
        if (algorithm == HashAlgorithmName.MD5) return new HMACMD5(key);
        if (algorithm == HashAlgorithmName.SHA1) return new HMACSHA1(key);
        if (algorithm == HashAlgorithmName.SHA256) return new HMACSHA256(key);
        if (algorithm == HashAlgorithmName.SHA384) return new HMACSHA384(key);
        if (algorithm == HashAlgorithmName.SHA512) return new HMACSHA512(key);

        throw new ArgumentException($"Непідтримуваний алгоритм: {algorithm.Name}");
    }
}
