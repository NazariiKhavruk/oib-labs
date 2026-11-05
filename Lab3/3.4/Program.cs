using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

Console.OutputEncoding = Encoding.UTF8;

int variant = 9;
int firstIterations = variant * 10_000;   // 90 000
int step = 50_000;
int pointsCount = 10;
int trials = 10;

int[] iterationCounts = new int[pointsCount];
for (int i = 0; i < pointsCount; i++)
    iterationCounts[i] = firstIterations + i * step;

var algorithms = new (string Name, HashAlgorithmName Algo)[]
{
    ("MD5", HashAlgorithmName.MD5),
    ("SHA1", HashAlgorithmName.SHA1),
    ("SHA256", HashAlgorithmName.SHA256),
    ("SHA384", HashAlgorithmName.SHA384),
    ("SHA512", HashAlgorithmName.SHA512),
};

string password = "MySecret123";

Console.WriteLine($"Варіант: {variant}, перша кількість ітерацій: {firstIterations}, крок: {step}, повторень: {trials}\n");

foreach (var (name, algo) in algorithms)
{
    Console.WriteLine($"Алгоритм {name}:");
    var pbkdf2 = new PBKDF2(algo);   // нова сіль для кожного алгоритму
    pbkdf2.ComputeHash(password, firstIterations);   // прогрів, щоб не врахувати JIT-компіляцію

    foreach (int iterations in iterationCounts)
    {
        var sw = Stopwatch.StartNew();
        for (int t = 0; t < trials; t++)
            pbkdf2.ComputeHash(password, iterations);
        sw.Stop();

        double avgMs = sw.Elapsed.TotalMilliseconds / trials;
        Console.WriteLine($"  ітерацій = {iterations,7}, середній час = {avgMs,9:F2} мс");
    }

    Console.WriteLine();
}

Console.WriteLine();
Console.WriteLine("Висновки:");
Console.WriteLine("Час обчислення PBKDF2 зростає приблизно лінійно зі збільшенням кількості ітерацій —");
Console.WriteLine("це і є метою навмисного уповільнення, що ускладнює атаку прямим перебором.");
Console.WriteLine("Швидкість алгоритмів різна: на цьому комп'ютері найшвидший SHA256, а MD5, SHA1,");
Console.WriteLine("SHA384 і SHA512 працюють повільніше при однаковій кількості ітерацій.");
