using SecureRnd;

for (int i = 1; i <= 5; i++)
{
    string value = Convert.ToBase64String(SecureRandomGenerator.GenerateRndBytes(32));
    Console.WriteLine($"Sproba {i}: {value}");
}