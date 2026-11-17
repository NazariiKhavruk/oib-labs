using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Lab6_3
{
    class Program
    {
        // Секретний ключ зберігається у контейнері, відкритий - у файлі
        private readonly static string CspContainerName = "RsaContainer";

        static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("1. Згенерувати ключі та зберегти відкритий ключ у файл");
                Console.WriteLine("2. Зашифрувати повідомлення відкритим ключем із файлу");
                Console.WriteLine("3. Розшифрувати повідомлення своїм секретним ключем");
                Console.WriteLine("4. Видалити ключі з контейнера");
                Console.WriteLine("0. Вихід");
                Console.Write("Оберіть дію: ");

                switch (Console.ReadLine())
                {
                    case "1":
                        Console.Write("Файл для відкритого ключа (Enter - public_key.xml): ");
                        string publicKeyPath = ReadOrDefault("public_key.xml");
                        GenerateOwnKeys(publicKeyPath);
                        Console.WriteLine($"Відкритий ключ збережено: {Path.GetFullPath(publicKeyPath)}");
                        break;

                    case "2":
                        Console.Write("Файл відкритого ключа отримувача (.xml): ");
                        string keyPath = Console.ReadLine() ?? "";
                        if (!File.Exists(keyPath))
                        {
                            Console.WriteLine("Файл не знайдено.");
                            break;
                        }
                        Console.Write("Повідомлення: ");
                        string message = Console.ReadLine() ?? "";
                        Console.Write("Файл для шифротексту (Enter - message.dat): ");
                        string cipherPath = ReadOrDefault("message.dat");

                        EncryptData(keyPath, Encoding.UTF8.GetBytes(message), cipherPath);
                        Console.WriteLine($"Зашифровано: {Convert.ToBase64String(File.ReadAllBytes(cipherPath))}");
                        Console.WriteLine($"Збережено у файл: {Path.GetFullPath(cipherPath)}");
                        break;

                    case "3":
                        Console.Write("Файл із шифротекстом (Enter - message.dat): ");
                        string path = ReadOrDefault("message.dat");
                        if (!File.Exists(path))
                        {
                            Console.WriteLine("Файл не знайдено.");
                            break;
                        }
                        try
                        {
                            byte[] plain = DecryptData(path);
                            Console.WriteLine($"Розшифровано: {Encoding.UTF8.GetString(plain)}");
                        }
                        catch (CryptographicException)
                        {
                            // Повідомлення зашифроване не нашим відкритим ключем
                            Console.WriteLine("Не вдалося розшифрувати: повідомлення зашифроване іншим ключем.");
                        }
                        break;

                    case "4":
                        DeleteKeyInCsp();
                        Console.WriteLine("Ключі видалено з контейнера.");
                        break;

                    case "0":
                        return;

                    default:
                        Console.WriteLine("Невірний вибір.");
                        break;
                }
            }
        }

        static string ReadOrDefault(string defaultValue)
        {
            string? input = Console.ReadLine();
            return string.IsNullOrWhiteSpace(input) ? defaultValue : input;
        }

        // Генерація ключів у контейнері та збереження відкритого ключа у файл
        public static void GenerateOwnKeys(string publicKeyPath)
        {
            CspParameters cspParameters = new CspParameters(1)
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore,
                ProviderName = "Microsoft Strong Cryptographic Provider"
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParameters))
            {
                rsa.PersistKeyInCsp = true;
                File.WriteAllText(publicKeyPath, rsa.ToXmlString(false));   // false - лише відкритий ключ
            }
        }

        // Зашифровування відкритим ключем отримувача (з файлу) та запис у файл
        public static void EncryptData(string publicKeyPath, byte[] dataToEncrypt, string chipherTextPath)
        {
            byte[] chipherBytes;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.FromXmlString(File.ReadAllText(publicKeyPath));
                chipherBytes = rsa.Encrypt(dataToEncrypt, true);
            }
            File.WriteAllBytes(chipherTextPath, chipherBytes);
        }

        // Розшифровування секретним ключем із контейнера
        public static byte[] DecryptData(string chipherTextPath)
        {
            byte[] chipherBytes = File.ReadAllBytes(chipherTextPath);
            byte[] plainTextBytes;
            var cspParams = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            using (var rsa = new RSACryptoServiceProvider(2048, cspParams))
            {
                rsa.PersistKeyInCsp = true;
                plainTextBytes = rsa.Decrypt(chipherBytes, true);
            }
            return plainTextBytes;
        }

        // Видалення ключів із контейнера
        public static void DeleteKeyInCsp()
        {
            CspParameters cspParameters = new CspParameters
            {
                KeyContainerName = CspContainerName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            var rsa = new RSACryptoServiceProvider(cspParameters)
            {
                PersistKeyInCsp = false
            };
            rsa.Clear();
        }
    }
}
