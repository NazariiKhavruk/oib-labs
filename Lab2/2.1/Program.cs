using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

byte[] Md5Hash(byte[] data)
{
    using var md5 = MD5.Create();
    return md5.ComputeHash(data);
}

byte[] Sha1Hash(byte[] data)
{
    using var sha1 = SHA1.Create();
    return sha1.ComputeHash(data);
}

byte[] Sha256Hash(byte[] data)
{
    using var sha256 = SHA256.Create();
    return sha256.ComputeHash(data);
}

byte[] Sha384Hash(byte[] data)
{
    using var sha384 = SHA384.Create();
    return sha384.ComputeHash(data);
}

byte[] Sha512Hash(byte[] data)
{
    using var sha512 = SHA512.Create();
    return sha512.ComputeHash(data);
}

void PrintHashes(string label, string text)
{
    byte[] data = Encoding.UTF8.GetBytes(text);

    byte[] md5 = Md5Hash(data);
    byte[] sha1 = Sha1Hash(data);
    byte[] sha256 = Sha256Hash(data);
    byte[] sha384 = Sha384Hash(data);
    byte[] sha512 = Sha512Hash(data);

    Console.WriteLine($"{label}: \"{text}\"");
    Console.WriteLine($"MD5    ({md5.Length,2} б): {Convert.ToBase64String(md5)}");
    Console.WriteLine($"SHA1   ({sha1.Length,2} б): {Convert.ToBase64String(sha1)}");
    Console.WriteLine($"SHA256 ({sha256.Length,2} б): {Convert.ToBase64String(sha256)}");
    Console.WriteLine($"SHA384 ({sha384.Length,2} б): {Convert.ToBase64String(sha384)}");
    Console.WriteLine($"SHA512 ({sha512.Length,2} б): {Convert.ToBase64String(sha512)}");
    Console.WriteLine();
}

PrintHashes("Рядок 1", "Hello World!");
PrintHashes("Рядок 2", "Hello World!");
PrintHashes("Рядок 3", "Hello world!");

Console.WriteLine("Висновки:");
Console.WriteLine("Рядок 1 і рядок 2 однакові — хеш-коди за всіма алгоритмами також однакові.");
Console.WriteLine("Рядок 3 відрізняється лише однією літерою, але хеш повністю інший (лавинний ефект).");
Console.WriteLine("Розмір хеш-коду: MD5 — 16 б, SHA1 — 20 б, SHA256 — 32 б, SHA384 — 48 б, SHA512 — 64 б.");
