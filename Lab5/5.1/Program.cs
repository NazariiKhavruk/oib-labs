using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;
Console.InputEncoding = Encoding.UTF8;

// Завдання 1: зашифровування та розшифровування DES, Triple-DES, AES.
// Ключ та вектор ініціалізації генеруються випадково.

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

    // Випадкові ключ та IV (GenerateKey/GenerateIV використовують криптостійкий генератор)
    alg.GenerateKey();
    alg.GenerateIV();

    Console.Write("Введіть текст для шифрування: ");
    string text = Console.ReadLine() ?? "";

    byte[] plain = Encoding.UTF8.GetBytes(text);
    byte[] encrypted = Encrypt(alg, plain);
    byte[] decrypted = Decrypt(alg, encrypted);

    Console.WriteLine($"Алгоритм:        {alg.GetType().BaseType?.Name ?? alg.GetType().Name} ({alg.KeySize} біт ключ, {alg.BlockSize} біт блок)");
    Console.WriteLine($"Ключ:            {Convert.ToHexString(alg.Key)}");
    Console.WriteLine($"IV:              {Convert.ToHexString(alg.IV)}");
    Console.WriteLine($"Шифротекст:      {Convert.ToHexString(encrypted)}");
    Console.WriteLine($"Розшифровано:    {Encoding.UTF8.GetString(decrypted)}");
}

static byte[] Encrypt(SymmetricAlgorithm alg, byte[] data)
{
    using ICryptoTransform encryptor = alg.CreateEncryptor();
    return encryptor.TransformFinalBlock(data, 0, data.Length);
}

static byte[] Decrypt(SymmetricAlgorithm alg, byte[] data)
{
    using ICryptoTransform decryptor = alg.CreateDecryptor();
    return decryptor.TransformFinalBlock(data, 0, data.Length);
}
