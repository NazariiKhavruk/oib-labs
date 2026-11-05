using System.Linq;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

string password = "MySecret123";

var sh1 = new SaltedHash(password);
var sh2 = new SaltedHash(password);

Console.WriteLine($"Пароль: \"{password}\"\n");

Console.WriteLine("Спроба 1:");
Console.WriteLine($"Сіль:  {Convert.ToBase64String(sh1.Salt)}");
Console.WriteLine($"Хеш: {Convert.ToBase64String(sh1.Hash)}\n");

Console.WriteLine("Спроба 2 (той же пароль, інша сіль):");
Console.WriteLine($"Сіль:  {Convert.ToBase64String(sh2.Salt)}");
Console.WriteLine($"Хеш: {Convert.ToBase64String(sh2.Hash)}\n");

Console.WriteLine($"Хеші однакового пароля однакові: {(SaltedHash.ComputeHash(password, sh1.Salt).SequenceEqual(sh1.Hash))}");
Console.WriteLine($"Хеш 1 і хеш 2 однакові, хоча пароль той же: {ByteArraysEqual(sh1.Hash, sh2.Hash)}\n");

Console.WriteLine("Перевірка пароля:");
Console.WriteLine($"Правильний пароль: {sh1.Verify(password)}");
Console.WriteLine($"Неправильний пароль: {sh1.Verify("інший_пароль")}");

Console.WriteLine();
Console.WriteLine("Висновки:");
Console.WriteLine("Додавання солі робить так, що однакові паролі дають різний хеш,");
Console.WriteLine("тому зловмисник не може скористатися заздалегідь обчисленими райдужними");
Console.WriteLine("таблицями для атаки на хеш-коди паролів.");

bool ByteArraysEqual(byte[] a, byte[] b)
{
    if (a.Length != b.Length) return false;
    for (int i = 0; i < a.Length; i++)
        if (a[i] != b[i]) return false;
    return true;
}
