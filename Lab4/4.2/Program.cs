using System.Text;

Console.OutputEncoding = Encoding.UTF8;

const string crib = "Mit21";
const int keyLength = 5;

Console.Write("Шлях до зашифрованого файлу (.dat): ");
string path = (Console.ReadLine() ?? "").Trim().Trim('"');

if (!File.Exists(path))
{
    Console.WriteLine("Файл не знайдено.");
    return;
}

byte[] cipher = File.ReadAllBytes(path);
byte[] cribBytes = Encoding.ASCII.GetBytes(crib);
string dir = Path.GetDirectoryName(path)!;
int candidates = 0;

Console.WriteLine($"Довжина файлу: {cipher.Length} байт");
Console.WriteLine();


for (int p = 0; p + cribBytes.Length <= cipher.Length; p++)
{
    byte[] keyFromCrib = new byte[keyLength];
    for (int i = 0; i < keyLength; i++)
        keyFromCrib[i] = (byte)(cipher[p + i] ^ cribBytes[i]);

    byte[] plain = new byte[cipher.Length];
    for (int j = 0; j < cipher.Length; j++)
        plain[j] = (byte)(cipher[j] ^ keyFromCrib[Mod(j - p, keyLength)]);

    if (!LooksLikeText(plain))
        continue;

    byte[] key = new byte[keyLength];
    for (int t = 0; t < keyLength; t++)
        key[t] = keyFromCrib[Mod(t - p, keyLength)];

    candidates++;
    Console.WriteLine($"Знайдено: фраза на позиції {p}, ключ = \"{Encoding.Latin1.GetString(key)}\"");

    string outPath = Path.Combine(dir, $"cracked_{p}.txt");
    File.WriteAllBytes(outPath, plain);
    Console.WriteLine($"  збережено: {outPath}");
}

Console.WriteLine();
Console.WriteLine(candidates == 0
    ? "Осмислених варіантів не знайдено."
    : $"Знайдено варіантів: {candidates}.");

Console.WriteLine();
Console.WriteLine("Висновки:");
Console.WriteLine("Ключ, що використовується повторно, легко відновити: достатньо знати шматок");
Console.WriteLine("відкритого тексту (фразу \"Mit21\") і зробити XOR із шифротекстом.");
Console.WriteLine("Це і є атака із вибором (або відомим) відкритим текстом. Перебір 5-символьного");
Console.WriteLine("ключа теж можливий, але з відомою фразою він не потрібен.");

static int Mod(int a, int m) => ((a % m) + m) % m;

// Перевірка, що байти є коректним UTF-8 без керуючих символів (крім переносів рядків і табуляції)
static bool LooksLikeText(byte[] data)
{
    string text;
    try
    {
        text = new UTF8Encoding(false, true).GetString(data);
    }
    catch (DecoderFallbackException)
    {
        return false;
    }

    return text.All(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t');
}
