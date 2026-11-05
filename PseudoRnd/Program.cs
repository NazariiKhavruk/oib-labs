Console.WriteLine("Odnakovyi seed (1234):");
var r1 = new Random(1234);
var r2 = new Random(1234);
for (int i = 0; i < 10; i++)
    Console.WriteLine($"{r1.Next(1, 101),4} {r2.Next(1, 101),4}");

Console.WriteLine("\nRiznyi seed (1234 i 4321):");
var r3 = new Random(1234);
var r4 = new Random(4321);
for (int i = 0; i < 10; i++)
    Console.WriteLine($"{r3.Next(1, 101),4} {r4.Next(1, 101),4}");