using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

int variant = 9;
int iterations = variant * 10_000;   // 90 000
HashAlgorithmName algorithm = HashAlgorithmName.SHA256;
const int saltLength = 32;

var users = new Dictionary<string, UserRecord>();   // зберігання в пам'яті

while (true)
{
    Console.WriteLine();
    Console.WriteLine("1. Реєстрація");
    Console.WriteLine("2. Автентифікація");
    Console.WriteLine("0. Вихід");
    Console.Write("Оберіть дію: ");

    string choice = Console.ReadLine() ?? "0";
    Console.WriteLine();

    switch (choice)
    {
        case "1":
            Register();
            break;
        case "2":
            Authenticate();
            break;
        case "0":
            return;
        default:
            Console.WriteLine("Невірний вибір.");
            break;
    }
}

void Register()
{
    Console.Write("Логін: ");
    string login = Console.ReadLine() ?? "";

    if (login.Length == 0)
    {
        Console.WriteLine("Логін не може бути порожнім.");
        return;
    }

    if (users.ContainsKey(login))
    {
        Console.WriteLine("Користувач із таким логіном уже існує.");
        return;
    }

    Console.Write("Пароль: ");
    string password = Console.ReadLine() ?? "";

    // нова сіль для кожного користувача
    byte[] salt = RandomNumberGenerator.GetBytes(saltLength);
    byte[] hash = new PBKDF2(algorithm, salt).ComputeHash(password, iterations);

    users[login] = new UserRecord(salt, hash);

    Console.WriteLine($"Користувача \"{login}\" зареєстровано.");
    Console.WriteLine($"Сіль:  {Convert.ToBase64String(salt)}");
    Console.WriteLine($"Хеш:   {Convert.ToBase64String(hash)}");
}

void Authenticate()
{
    Console.Write("Логін: ");
    string login = Console.ReadLine() ?? "";

    Console.Write("Пароль: ");
    string password = Console.ReadLine() ?? "";

    // однакова відповідь для неіснуючого логіну і неправильного пароля
    if (!users.TryGetValue(login, out UserRecord? record))
    {
        Console.WriteLine("Невірний логін або пароль.");
        return;
    }

    byte[] candidate = new PBKDF2(algorithm, record.Salt).ComputeHash(password, iterations);

    if (CryptographicOperations.FixedTimeEquals(candidate, record.Hash))
        Console.WriteLine($"Автентифікацію пройдено: вітаємо, {login}.");
    else
        Console.WriteLine("Невірний логін або пароль.");
}

// Зберігаємо сіль і хеш, але не сам пароль.
record UserRecord(byte[] Salt, byte[] Hash);
