using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

// Завдання 2: ключ та IV формуються з пароля через Rfc2898DeriveBytes (PBKDF2).
// Сіль - випадкові байти, кількість ітерацій = варіант * 10 000.
const int variant = 9;
const int iterations = variant * 10_000;   // 90 000
const int saltSize = 16;

while (true)
{
    Console.WriteLine();
    Console.WriteLine("Алгоритм: 1 - DES, 2 - Triple-DES, 3 - AES, 0 - вихід");
    Console.Write("Оберіть: ");
    string? choice = Console.ReadLine();
    if (choice == "0") return;

    using SymmetricAlgorithm? alg = choice switch
    {
        "1" => DES.Create(),
        "2" => TripleDES.Create(),
        "3" => Aes.Create(),
        _ => null
    };
    if (alg == null)
    {
        Console.WriteLine("Невірний вибір.");
        continue;
    }

    Console.Write("Введіть пароль: ");
    string password = Console.ReadLine() ?? "";
    Console.Write("Введіть текст для шифрування: ");
    string text = Console.ReadLine() ?? "";

    // Зашифровування: нова випадкова сіль
    byte[] salt = RandomNumberGenerator.GetBytes(saltSize);
    DeriveKeyAndIv(alg, password, salt);

    byte[] encrypted;
    using (ICryptoTransform enc = alg.CreateEncryptor())
    {
        byte[] plain = Encoding.UTF8.GetBytes(text);
        encrypted = enc.TransformFinalBlock(plain, 0, plain.Length);
    }

    Console.WriteLine($"Ітерацій:        {iterations}");
    Console.WriteLine($"Сіль:            {Convert.ToHexString(salt)}");
    Console.WriteLine($"Ключ:            {Convert.ToHexString(alg.Key)}");
    Console.WriteLine($"IV:              {Convert.ToHexString(alg.IV)}");
    Console.WriteLine($"Шифротекст:      {Convert.ToHexString(encrypted)}");

    // Розшифровування: ключ та IV відновлюються з пароля і збереженої солі
    Console.Write("Введіть пароль для розшифрування: ");
    string password2 = Console.ReadLine() ?? "";
    DeriveKeyAndIv(alg, password2, salt);
    try
    {
        using ICryptoTransform dec = alg.CreateDecryptor();
        byte[] decrypted = dec.TransformFinalBlock(encrypted, 0, encrypted.Length);
        Console.WriteLine($"Розшифровано:    {Encoding.UTF8.GetString(decrypted)}");
    }
    catch (CryptographicException)
    {
        Console.WriteLine("Не вдалося розшифрувати: невірний пароль.");
    }
}

static void DeriveKeyAndIv(SymmetricAlgorithm alg, string password, byte[] salt)
{
    int keyBytes = alg.KeySize / 8;
    int ivBytes = alg.BlockSize / 8;

    using var kdf = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA256);
    alg.Key = kdf.GetBytes(keyBytes);
    alg.IV = kdf.GetBytes(ivBytes);
}
