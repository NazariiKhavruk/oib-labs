using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

bool HashesEqual(byte[] a, byte[] b)
{
    if (a.Length != b.Length) return false;
    for (int i = 0; i < a.Length; i++)
        if (a[i] != b[i]) return false;
    return true;
}

string targetGuid = "41664ae3-8eeb-be01-f730-cdb5e6f6ce4e";
byte[] targetHash = new Guid(targetGuid).ToByteArray();

Console.WriteLine($"Відомий MD5 хеш: {{{targetGuid}}}");
Console.WriteLine("Пароль складається з 8 цифр, перебираємо всі варіанти від 00000000 до 99999999\n");

long total = 100_000_000L;
string found = "";
var sw = Stopwatch.StartNew();

using (var md5 = MD5.Create())
{
    for (long i = 0; i < total; i++)
    {
        string candidate = i.ToString("D8");
        byte[] candidateHash = md5.ComputeHash(Encoding.UTF8.GetBytes(candidate));

        if (HashesEqual(candidateHash, targetHash))
        {
            found = candidate;
            break;
        }
    }
}

sw.Stop();

if (found != "")
{
    Console.WriteLine($"Пароль знайдено: {found}");
    Console.WriteLine($"Час перебору: {sw.Elapsed.TotalSeconds:F2} с.");
}
else
{
    Console.WriteLine("Пароль не знайдено.");
}

Console.WriteLine();
Console.WriteLine("Висновки:");
Console.WriteLine("Всіх варіантів 8-значного числового пароля лише 10^8 = 100000000,");
Console.WriteLine("тому звичайний комп'ютер перебирає їх усі за прийнятний час.");
Console.WriteLine("Це означає, що пароль лише з цифр фіксованої довжини — ненадійний.");
Console.WriteLine("Для надійного пароля потрібен більший алфавіт символів (букви, цифри,");
Console.WriteLine("спецсимволи) і більша довжина, а зберігати паролі краще не простим хешем,");
Console.WriteLine("а функціями типу PBKDF2 або bcrypt з сіллю.");
