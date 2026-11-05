using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

while (true)
{
    Console.WriteLine();
    Console.WriteLine("1. Зашифрувати файл");
    Console.WriteLine("2. Розшифрувати файл");
    Console.WriteLine("0. Вихід");
    Console.Write("Оберіть дію: ");

    switch (Console.ReadLine())
    {
        case "1":
            Encrypt();
            break;
        case "2":
            Decrypt();
            break;
        case "0":
            return;
        default:
            Console.WriteLine("Невірний вибір.");
            break;
    }
}

void Encrypt()
{
    string? path = AskExistingFile("Шлях до файлу для шифрування: ");
    if (path == null) return;

    byte[] data = File.ReadAllBytes(path);

    // Ключ Вернама: випадковий, такої ж довжини, як файл, використовується один раз
    byte[] key = RandomNumberGenerator.GetBytes(data.Length);
    byte[] encrypted = Xor(data, key);

    string datPath = Path.ChangeExtension(path, ".dat");
    File.WriteAllBytes(datPath, encrypted);

    // Ключ зберігаємо окремо: без нього розшифрувати файл неможливо
    string keyPath = Path.ChangeExtension(path, ".key");
    using (var writer = new BinaryWriter(File.Create(keyPath)))
    {
        writer.Write(Path.GetFileName(path));   // ім'я оригінального файлу
        writer.Write(key);                      // сам ключ
    }

    Console.WriteLine($"Зашифровано: {datPath}");
    Console.WriteLine($"Ключ збережено: {keyPath}");
}

void Decrypt()
{
    string? datPath = AskExistingFile("Шлях до зашифрованого файлу (.dat): ");
    if (datPath == null) return;

    string keyPath = Path.ChangeExtension(datPath, ".key");
    if (!File.Exists(keyPath))
    {
        Console.WriteLine($"Не знайдено файл ключа: {keyPath}");
        return;
    }

    string originalName;
    byte[] key;
    using (var reader = new BinaryReader(File.OpenRead(keyPath)))
    {
        originalName = reader.ReadString();
        key = reader.ReadBytes((int)(reader.BaseStream.Length - reader.BaseStream.Position));
    }

    byte[] encrypted = File.ReadAllBytes(datPath);
    if (key.Length != encrypted.Length)
    {
        Console.WriteLine("Ключ не відповідає цьому файлу (різна довжина).");
        return;
    }

    byte[] decrypted = Xor(encrypted, key);

    // Щоб не перезаписати оригінал, результат зберігаємо з префіксом
    string outPath = Path.Combine(Path.GetDirectoryName(datPath)!, "decrypted_" + originalName);
    File.WriteAllBytes(outPath, decrypted);

    Console.WriteLine($"Розшифровано: {outPath}");
}

string? AskExistingFile(string prompt)
{
    Console.Write(prompt);
    string path = (Console.ReadLine() ?? "").Trim().Trim('"');

    if (!File.Exists(path))
    {
        Console.WriteLine("Файл не знайдено.");
        return null;
    }

    return path;
}

// Операція XOR байт за байтом. Для шифрування й розшифрування однакова.
byte[] Xor(byte[] data, byte[] key)
{
    byte[] result = new byte[data.Length];
    for (int i = 0; i < data.Length; i++)
        result[i] = (byte)(data[i] ^ key[i]);
    return result;
}
