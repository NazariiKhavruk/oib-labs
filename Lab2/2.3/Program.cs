using System.Text;

Console.OutputEncoding = Encoding.UTF8;

byte[] key = HmacHelper.GenerateKey(32);
Console.WriteLine($"Згенерований секретний ключ: {Convert.ToBase64String(key)}\n");

string message = "Hello World!";
byte[] data = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Повідомлення: \"{message}\"");
Console.WriteLine($"HMAC-MD5:    {Convert.ToBase64String(HmacHelper.ComputeMd5(data, key))}");
Console.WriteLine($"HMAC-SHA1:   {Convert.ToBase64String(HmacHelper.ComputeSha1(data, key))}");
Console.WriteLine($"HMAC-SHA256: {Convert.ToBase64String(HmacHelper.ComputeSha256(data, key))}");
Console.WriteLine($"HMAC-SHA512: {Convert.ToBase64String(HmacHelper.ComputeSha512(data, key))}\n");

byte[] originalHmac = HmacHelper.ComputeSha256(data, key);
Console.WriteLine($"Відправник надсилає повідомлення і HMAC-SHA256: {Convert.ToBase64String(originalHmac)}\n");

bool check1 = HmacHelper.Verify(message, originalHmac, key);
Console.WriteLine($"Перевірка 1, повідомлення не змінене: {(check1 ? "підтверджено" : "відхилено")}");

string tampered = "Hello World?";
bool check2 = HmacHelper.Verify(tampered, originalHmac, key);
Console.WriteLine($"Перевірка 2, повідомлення підмінено на \"{tampered}\": {(check2 ? "підтверджено" : "відхилено")}");

byte[] wrongKey = HmacHelper.GenerateKey(32);
bool check3 = HmacHelper.Verify(message, originalHmac, wrongKey);
Console.WriteLine($"Перевірка 3, перевірка з чужим секретним ключем: {(check3 ? "підтверджено" : "відхилено")}");

Console.WriteLine();
Console.WriteLine("Висновки:");
Console.WriteLine("HMAC одночасно перевіряє цілісність (дані не пошкоджені) та автентичність");
Console.WriteLine("(повідомлення надіслане тим, хто знає секретний ключ). Без правильного");
Console.WriteLine("ключа неможливо згенерувати правильний HMAC, тому підміна повідомлення");
Console.WriteLine("або використання чужого ключа одразу виявляється при перевірці.");
