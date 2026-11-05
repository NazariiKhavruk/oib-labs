using System.Text;

byte[] key = HmacHelper.GenerateKey(32);
Console.WriteLine($"Zghenerovanyi sekretnyi kliuch: {Convert.ToBase64String(key)}\n");

string message = "Hello World!";
byte[] data = Encoding.UTF8.GetBytes(message);

Console.WriteLine($"Povidomlennia: \"{message}\"");
Console.WriteLine($"HMAC-MD5:    {Convert.ToBase64String(HmacHelper.ComputeMd5(data, key))}");
Console.WriteLine($"HMAC-SHA1:   {Convert.ToBase64String(HmacHelper.ComputeSha1(data, key))}");
Console.WriteLine($"HMAC-SHA256: {Convert.ToBase64String(HmacHelper.ComputeSha256(data, key))}");
Console.WriteLine($"HMAC-SHA512: {Convert.ToBase64String(HmacHelper.ComputeSha512(data, key))}\n");

byte[] originalHmac = HmacHelper.ComputeSha256(data, key);
Console.WriteLine($"Vidpravnyk nadsylaie povidomlennia i HMAC-SHA256: {Convert.ToBase64String(originalHmac)}\n");

bool check1 = HmacHelper.Verify(message, originalHmac, key);
Console.WriteLine($"Perevirka 1, povidomlennia ne zminene: {(check1 ? "pidtverdzheno" : "vidkhyleno")}");

string tampered = "Hello World?";
bool check2 = HmacHelper.Verify(tampered, originalHmac, key);
Console.WriteLine($"Perevirka 2, povidomlennia pidmineno na \"{tampered}\": {(check2 ? "pidtverdzheno" : "vidkhyleno")}");

byte[] wrongKey = HmacHelper.GenerateKey(32);
bool check3 = HmacHelper.Verify(message, originalHmac, wrongKey);
Console.WriteLine($"Perevirka 3, perevirka z chuzhym sekretnym kliuchem: {(check3 ? "pidtverdzheno" : "vidkhyleno")}");

Console.WriteLine();
Console.WriteLine("Visnovky:");
Console.WriteLine("HMAC odnochasno pereviriaie tsilisnist (dani ne poshkodzheni) ta avtentychnist");
Console.WriteLine("(povidomlennia nadislane tym, khto znaie sekretnyi kliuch). Bez pravylnoho");
Console.WriteLine("kliucha nemozhlyvo zgheneruvaty pravylnyi HMAC, tomu pidmina povidomlennia");
Console.WriteLine("abo vykorystannia chuzhoho kliucha odrazu vyiavliaietsia pry perevirtsi.");
